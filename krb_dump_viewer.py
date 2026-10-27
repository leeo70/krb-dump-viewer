#!/usr/bin/env python3
"""
krb_dump_viewer.py

Multi-file GUI viewer for Kerbeus-BOF krb_dump output.
Each file becomes an isolated tab; inside, users and tickets become
collapsible blocks with risk tagging (TGT, honey, pre-authent, etc).

Accepts files AND directories on the command line and from the UI.

Usage:
    python krb_dump_viewer.py                       # empty, open from UI
    python krb_dump_viewer.py dump1.txt dump2.txt   # individual files
    python krb_dump_viewer.py .\\dumps\\              # all dumps in a dir
    python krb_dump_viewer.py .\\dumps\\ .\\other\\     # multiple dirs
    python krb_dump_viewer.py .\\dumps\\ .\\dump.txt   # mixed
"""

import os
import sys
import re
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass, field, asdict
from typing import List, Optional

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
RE_RECEIVED_OUTPUT = re.compile(r'^\[\d{2}/\d{2} \d{2}:\d{2}:\d{2}\]\s+\[\+\]\s+received output:\s*$')
RE_TICKET_INDEX = re.compile(r'^\[(\d+)\]\s*$')
RE_CACHED_TICKETS = re.compile(r'^\[\*\]\s+Cached tickets:\s*\((\d+)\)\s*$')
RE_USER_FIELD = re.compile(
    r'^(UserName|Domain|LogonId|Session|UserSID|'
    r'Authentication package|LogonServer|UserPrincipalName)\s*:\s*(.*)$'
)
RE_TICKET_FIELD = re.compile(
    r'^\s+(ClientName|ServiceRealm|'
    r'StartTime \(UTC\)|EndTime \(UTC\)|RenewTill \(UTC\)|'
    r'Flags|KeyType)\s*:\s*(.*)$'
)
RE_BASE64_ONLY = re.compile(r'^[A-Za-z0-9+/=]+$')


# ---------------------------------------------------------------------------
# Contexto CRTO: SIDs privilegiados + honey patterns
# ---------------------------------------------------------------------------
# RIDs well-known de contas/grupos de alto privilégio (TGT nesses = jogo)
HIGH_PRIV_RIDS = {
    '500': 'Admin',
    '512': 'DomainAdmins',
    '518': 'SchemaAdmins',
    '519': 'EnterpriseAdmins',
    '520': 'GroupPolicyCreators',
    '544': 'BUILTIN-Admins',
    '548': 'AccountOperators',
    '549': 'ServerOperators',
}

# Honey / decoy patterns. Edit this tuple for your target environment.
# Any ticket whose client_name or service_realm contains one of these
# substrings (case-insensitive) is flagged HONEY in the UI.
# Examples you might add during an engagement:
#   'honeysvc/'           SPN patterns suggesting canary services
#   'mssqlsvc/host-that-does-not-exist'
#   '<decoy-user-samaccountname>'
HONEY_PATTERNS: tuple = (
    # 'honeysvc/',
    # 'honey',
)


# ---------------------------------------------------------------------------
# Expansao de entrada: aceita arquivos OU diretorios
# ---------------------------------------------------------------------------
DUMP_EXTENSIONS = ('.txt', '.log', '.dump')


def _is_dump_file(name: str) -> bool:
    """Heuristica: extensoes conhecidas, ou arquivos sem extensao."""
    try:
        low = name.lower()
        if low.startswith('.'):
            return False
        if any(low.endswith(ext) for ext in DUMP_EXTENSIONS):
            return True
        return '.' not in low
    except Exception:
        return False


def expand_input_paths(paths, recursive: bool = False):
    """
    Recebe arquivos e/ou diretorios e devolve (lista_de_arquivos, avisos).
    - Diretorio: pega *.txt/*.log/*.dump (ou sem extensao) dentro dele.
    - Arquivo: passa direto.
    - Deduplica por caminho absoluto, mantendo ordem.
    """
    files, warnings = [], []
    for p in (paths or []):
        try:
            if os.path.isdir(p):
                if recursive:
                    for root, _, names in os.walk(p):
                        for n in sorted(names):
                            if _is_dump_file(n):
                                files.append(os.path.join(root, n))
                else:
                    for n in sorted(os.listdir(p)):
                        full = os.path.join(p, n)
                        try:
                            if os.path.isfile(full) and _is_dump_file(n):
                                files.append(full)
                        except OSError:
                            continue
            elif os.path.isfile(p):
                files.append(p)
            else:
                warnings.append(f'ignorado (nao existe): {p}')
        except Exception as e:
            warnings.append(f'erro ao expandir {p}: {e}')

    seen, out = set(), []
    for f in files:
        try:
            key = os.path.abspath(f)
        except Exception:
            key = f
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out, warnings


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
@dataclass
class Ticket:
    index: int
    client_name: str = ''
    service_realm: str = ''
    start_time: str = ''
    end_time: str = ''
    renew_till: str = ''
    flags: str = ''
    key_type: str = ''
    blob: Optional[str] = None


@dataclass
class UserEntry:
    user_name: str = ''
    domain: str = ''
    logon_id: str = ''
    session: str = ''
    user_sid: str = ''
    auth_package: str = ''
    logon_server: str = ''
    upn: str = ''
    tickets_declared: int = 0
    tickets: List[Ticket] = field(default_factory=list)


@dataclass
class ParseResult:
    tool_header: str = ''
    action: str = ''
    users: List[UserEntry] = field(default_factory=list)
    orphan_blobs: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def looks_like_kirbi(line: str) -> bool:
    try:
        s = line.strip()
        if len(s) < 200:
            return False
        # DER base64 de KRB-CRED começa tipicamente com doI/doH/doJ;
        # alguns dumps raros entregam MII (formato alternativo).
        if not (s.startswith('doI') or s.startswith('doH')
                or s.startswith('doJ') or s.startswith('MII')):
            return False
        return bool(RE_BASE64_ONLY.fullmatch(s))
    except Exception:
        return False


def is_honey_ticket(t: 'Ticket') -> bool:
    try:
        svc = (t.service_realm or '').lower()
        cli = (t.client_name or '').lower()
        return any(p in svc or p in cli for p in HONEY_PATTERNS)
    except Exception:
        return False


def is_honey_user(u: 'UserEntry') -> bool:
    try:
        name = (u.user_name or '').lower()
        upn = (u.upn or '').lower()
        return any(p in name or p in upn for p in HONEY_PATTERNS)
    except Exception:
        return False


def risk_flags(t: 'Ticket') -> List[str]:
    out = []
    try:
        realm = (t.service_realm or '').lower()
        flags = (t.flags or '').lower()
        if realm.startswith('krbtgt/'):
            out.append('TGT')
        if 'ok_as_delegate' in flags:
            out.append('ok_as_delegate')
        # forwardable e forwarded são distintos; nenhum é substring do outro
        if 'forwardable' in flags:
            out.append('forwardable')
        if 'forwarded' in flags:
            out.append('forwarded')
        if 'pre_authent' in flags or 'pre-authent' in flags:
            out.append('pre_authent')
        if 'renewable' in flags:
            out.append('renewable')
        if is_honey_ticket(t):
            out.append('HONEY')
        out.append('blob_exposto' if t.blob else 'sem_blob')
    except Exception:
        pass
    return out


def parse_file(path: str) -> ParseResult:
    result = ParseResult()
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    current_user: Optional[UserEntry] = None
    current_ticket: Optional[Ticket] = None

    def finalize_ticket():
        nonlocal current_ticket
        try:
            if current_ticket is not None and current_user is not None:
                current_user.tickets.append(current_ticket)
        finally:
            current_ticket = None

    def finalize_user():
        nonlocal current_user
        try:
            finalize_ticket()
            if current_user is not None:
                result.users.append(current_user)
        finally:
            current_user = None

    for lineno, raw in enumerate(lines, 1):
        try:
            line = raw.rstrip('\n').rstrip('\r')
            s = line.strip()
            if not s:
                continue

            if 'Kerbeus DUMP by' in s:
                result.tool_header = s
                continue

            if s.startswith('Action:'):
                result.action = s.split(':', 1)[1].strip() if ':' in s else s
                continue

            if RE_RECEIVED_OUTPUT.match(s):
                continue

            m = RE_CACHED_TICKETS.match(s)
            if m:
                if current_user is not None:
                    try:
                        current_user.tickets_declared = int(m.group(1))
                    except ValueError:
                        pass
                continue

            m = RE_TICKET_INDEX.match(s)
            if m:
                finalize_ticket()
                try:
                    idx = int(m.group(1))
                except ValueError:
                    idx = 0
                current_ticket = Ticket(index=idx)
                continue

            m = RE_USER_FIELD.match(s)
            if m:
                key, value = m.group(1), m.group(2).strip()
                if key == 'UserName':
                    finalize_user()
                    current_user = UserEntry(user_name=value)
                elif current_user is not None:
                    if key == 'Domain':
                        current_user.domain = value
                    elif key == 'LogonId':
                        current_user.logon_id = value
                    elif key == 'Session':
                        current_user.session = value
                    elif key == 'UserSID':
                        current_user.user_sid = value
                    elif key == 'Authentication package':
                        current_user.auth_package = value
                    elif key == 'LogonServer':
                        current_user.logon_server = value
                    elif key == 'UserPrincipalName':
                        current_user.upn = value
                continue

            m = RE_TICKET_FIELD.match(line)
            if m and current_ticket is not None:
                key, value = m.group(1), m.group(2).strip()
                if key == 'ClientName':
                    current_ticket.client_name = value
                elif key == 'ServiceRealm':
                    current_ticket.service_realm = value
                elif key == 'StartTime (UTC)':
                    current_ticket.start_time = value
                elif key == 'EndTime (UTC)':
                    current_ticket.end_time = value
                elif key == 'RenewTill (UTC)':
                    current_ticket.renew_till = value
                elif key == 'Flags':
                    current_ticket.flags = value
                elif key == 'KeyType':
                    current_ticket.key_type = value
                continue

            if looks_like_kirbi(s):
                # Sem dedup global: o mesmo material kirbi pode aparecer
                # repetido em S4U/altservice e é esperado ter blob em cada
                # ticket. Dedup só evita duplicata no MESMO ticket.
                if current_ticket is not None and current_ticket.blob is None:
                    current_ticket.blob = s
                elif current_ticket is not None and current_ticket.blob == s:
                    pass  # repetição no mesmo ticket, ignora
                else:
                    result.orphan_blobs.append(s)
                continue

        except Exception as e:
            result.warnings.append(f'linha {lineno}: {e}')

    finalize_user()

    for u in result.users:
        if u.tickets_declared and u.tickets_declared != len(u.tickets):
            result.warnings.append(
                f'{u.user_name}: declarado {u.tickets_declared}, encontrado {len(u.tickets)}'
            )
    if not result.users:
        result.errors.append('nenhum usuario extraido')

    return result


# ---------------------------------------------------------------------------
# CollapsibleFrame
# ---------------------------------------------------------------------------
class CollapsibleFrame(ttk.Frame):
    def __init__(self, parent, title, subtitle='', start_open=False, kind='user', **kw):
        super().__init__(parent, **kw)
        self._expanded = start_open
        self._kind = kind

        if kind == 'user':
            bg, fg, hover = '#dbe9f7', '#0a2a52', '#c5dcf2'
        elif kind == 'critical':
            bg, fg, hover = '#ffd6d6', '#7a1010', '#ffc0c0'
        else:
            bg, fg, hover = '#f0f0f0', '#333333', '#e2e2e2'
        self._bg = bg
        self._hover = hover

        title_font = (('Segoe UI', 11, 'bold') if kind in ('user', 'critical')
                      else ('Segoe UI', 10, 'bold'))

        self.header = tk.Frame(self, bg=bg, cursor='hand2')
        self.header.pack(fill='x')

        self.arrow = tk.Label(self.header,
                              text='\u25b6' if not start_open else '\u25bc',
                              bg=bg, fg=fg, font=title_font, width=2)
        self.arrow.pack(side='left', padx=(6, 0), pady=4)

        self.title_lbl = tk.Label(self.header, text=title, bg=bg, fg=fg,
                                  font=title_font, anchor='w')
        self.title_lbl.pack(side='left', fill='x', expand=True, padx=(4, 4))

        self.sub_lbl = tk.Label(self.header, text=subtitle, bg=bg, fg=fg,
                                font=('Segoe UI', 9), anchor='e')
        self.sub_lbl.pack(side='right', padx=(4, 10))

        self._children = [self.header, self.arrow, self.title_lbl, self.sub_lbl]
        for w in self._children:
            w.bind('<Button-1>', self._toggle)
            w.bind('<Enter>', self._enter)
            w.bind('<Leave>', self._leave)

        ttk.Separator(self, orient='horizontal').pack(fill='x')

        self.content = ttk.Frame(self, padding=(20, 6, 6, 10))
        if start_open:
            self.content.pack(fill='x', expand=True)

    def _set_bg(self, color):
        for w in self._children:
            try:
                w.configure(bg=color)
            except Exception:
                pass

    def _enter(self, _=None):
        self._set_bg(self._hover)

    def _leave(self, _=None):
        self.after(1, self._check_leave)

    def _check_leave(self):
        try:
            x, y = self.header.winfo_pointerxy()
            child = self.header.winfo_containing(x, y)
            w = child
            while w is not None:
                if w is self.header:
                    return
                w = getattr(w, 'master', None)
            self._set_bg(self._bg)
        except Exception:
            self._set_bg(self._bg)

    def _toggle(self, _=None):
        try:
            if self._expanded:
                self.content.pack_forget()
                self.arrow.configure(text='\u25b6')
                self._expanded = False
            else:
                self.content.pack(fill='x', expand=True)
                self.arrow.configure(text='\u25bc')
                self._expanded = True
        except Exception as e:
            print(f'[!] toggle: {e}')

    def set_expanded(self, expanded: bool):
        """For\u00e7a o estado de expans\u00e3o sem depender de clique."""
        try:
            if expanded and not self._expanded:
                self.content.pack(fill='x', expand=True)
                self.arrow.configure(text='\u25bc')
                self._expanded = True
            elif not expanded and self._expanded:
                self.content.pack_forget()
                self.arrow.configure(text='\u25b6')
                self._expanded = False
        except Exception as e:
            print(f'[!] set_expanded: {e}')

    def set_visible(self, visible: bool):
        """Esconde/mostra o bloco inteiro (para filtro)."""
        try:
            if visible:
                if not self.winfo_ismapped():
                    self.pack(fill='x', pady=(0, 6))
            else:
                self.pack_forget()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ScrollableFrame
# ---------------------------------------------------------------------------
class ScrollableFrame(ttk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self.canvas = tk.Canvas(self, highlightthickness=0, bg='#f5f5f5')
        self.vsb = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.vsb.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        self.inner = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor='nw')

        self.inner.bind('<Configure>',
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>',
                         lambda e: self.canvas.itemconfigure(self._win, width=e.width))

    def scroll_by(self, delta):
        try:
            self.canvas.yview_scroll(int(-1 * (delta / 120)), 'units')
        except Exception:
            pass


# ---------------------------------------------------------------------------
# FileTab
# ---------------------------------------------------------------------------
class FileTab(ttk.Frame):
    def __init__(self, parent, app, path: str, result: ParseResult):
        super().__init__(parent, padding=0)
        self.app = app
        self.path = path
        self.result = result
        # user_frames guarda (user_entry, CollapsibleFrame do user,
        # [(ticket, CollapsibleFrame do ticket), ...]) para filtro.
        self._user_frames: list = []
        self._filter_var: Optional[tk.StringVar] = None
        self._build()

    def _build(self):
        top = ttk.Frame(self, padding=(10, 6, 10, 2))
        top.pack(fill='x')
        ttk.Label(top, text=self.path, font=('Segoe UI', 9, 'italic'),
                  foreground='#555').pack(anchor='w')

        # Barra de filtro + ações
        bar = ttk.Frame(self, padding=(10, 2, 10, 2))
        bar.pack(fill='x')
        ttk.Label(bar, text='Filtro:').pack(side='left', padx=(0, 4))
        self._filter_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self._filter_var, width=40)
        entry.pack(side='left', padx=(0, 6))
        entry.bind('<KeyRelease>', lambda _e: self._apply_filter())
        ttk.Button(bar, text='Limpar',
                   command=self._clear_filter).pack(side='left', padx=(0, 10))
        ttk.Button(bar, text='Expandir tudo',
                   command=lambda: self._set_all_expanded(True)
                   ).pack(side='left', padx=(0, 4))
        ttk.Button(bar, text='Colapsar tudo',
                   command=lambda: self._set_all_expanded(False)
                   ).pack(side='left', padx=(0, 10))
        ttk.Button(bar, text='Exportar JSON',
                   command=self._export_json).pack(side='left')

        summary = tk.Frame(self, bg='white',
                           highlightbackground='#d0d0d0', highlightthickness=1)
        summary.pack(fill='x', padx=10, pady=(2, 4))

        total_tickets = sum(len(u.tickets) for u in self.result.users)
        total_blobs = (sum(1 for u in self.result.users for t in u.tickets if t.blob)
                       + len(self.result.orphan_blobs))
        total_honey = sum(1 for u in self.result.users
                          for t in u.tickets if is_honey_ticket(t))
        stats = [
            ('Usuarios', len(self.result.users), '#1565c0'),
            ('Tickets', total_tickets, '#1565c0'),
            ('Blobs', total_blobs, '#1565c0'),
            ('Honey', total_honey, '#b71c1c'),
            ('Avisos', len(self.result.warnings), '#ef6c00'),
            ('Erros', len(self.result.errors), '#c62828'),
        ]
        for key, value, color in stats:
            f = tk.Frame(summary, bg='white')
            f.pack(side='left', padx=16, pady=6)
            tk.Label(f, text=str(value), bg='white', fg=color,
                     font=('Segoe UI', 14, 'bold')).pack()
            tk.Label(f, text=key, bg='white', fg='#666',
                     font=('Segoe UI', 8)).pack()

        scroll = ScrollableFrame(self)
        scroll.pack(fill='both', expand=True, padx=10, pady=8)
        self._populate(scroll.inner)

    def _populate(self, parent):
        r = self.result
        if r.tool_header or r.action:
            info = ttk.Frame(parent)
            info.pack(fill='x', pady=(0, 8))
            if r.tool_header:
                ttk.Label(info, text=r.tool_header,
                          font=('Segoe UI', 10)).pack(anchor='w')
            if r.action:
                ttk.Label(info, text=f'Acao: {r.action}',
                          foreground='#666').pack(anchor='w')

        if not r.users:
            ttk.Label(parent, text='Nenhum usuario extraido.',
                      foreground='#c62828', padding=20).pack()

        for u in r.users:
            self._user_block(parent, u)

        if r.orphan_blobs:
            self._orphan_block(parent, r.orphan_blobs)
        if r.warnings:
            self._list_block(parent, 'Avisos', r.warnings, '#ef6c00')
        if r.errors:
            self._list_block(parent, 'Erros', r.errors, '#c62828')

    def _user_block(self, parent, u: UserEntry):
        try:
            risk = self._user_risk(u)
            # 'critical' marca linhas vermelhas: TGT privilegiado ou honey.
            is_crit = ('TGT-Admin' in risk
                       or 'TGT-DomainAdmins' in risk
                       or 'TGT-EnterpriseAdmins' in risk
                       or 'TGT-SchemaAdmins' in risk
                       or 'HONEY' in risk)
            kind = 'critical' if is_crit else 'user'
            subtitle = f'{len(u.tickets)} ticket(s)  |  {u.auth_package or "-"}'
            if risk:
                subtitle += f'  |  {risk}'
            title = f'{u.user_name or "(sem nome)"}  @  {u.domain or "-"}'

            cf = CollapsibleFrame(parent, title=title, subtitle=subtitle,
                                  start_open=False, kind=kind)
            cf.pack(fill='x', pady=(0, 6))
            ticket_frames: list = []
            self._user_frames.append((u, cf, ticket_frames))

            grid = ttk.Frame(cf.content)
            grid.pack(fill='x', pady=(4, 6))
            fields = [
                ('LogonId', u.logon_id), ('Session', u.session),
                ('UserSID', u.user_sid), ('Auth package', u.auth_package),
                ('LogonServer', u.logon_server), ('UPN', u.upn),
                ('Tickets declarados', str(u.tickets_declared)),
                ('Tickets encontrados', str(len(u.tickets))),
            ]
            for i, (k, v) in enumerate(fields):
                row, col = i // 2, (i % 2) * 2
                ttk.Label(grid, text=f'{k}:', foreground='#555',
                          font=('Segoe UI', 9)).grid(row=row, column=col,
                                                     sticky='w', padx=(0, 4), pady=1)
                ttk.Label(grid, text=v or '-', foreground='#111',
                          font=('Consolas', 9)).grid(row=row, column=col + 1,
                                                     sticky='w', padx=(0, 24), pady=1)

            if not u.tickets:
                ttk.Label(cf.content, text='(sem tickets)', foreground='#888',
                          padding=(0, 6)).pack(anchor='w')
            else:
                for t in u.tickets:
                    tcf = self._ticket_block(cf.content, t)
                    if tcf is not None:
                        ticket_frames.append((t, tcf))
        except Exception as e:
            print(f'[!] user_block: {e}')

    def _ticket_block(self, parent, t: Ticket):
        try:
            risks = risk_flags(t)
            subtitle = t.service_realm or '-'
            if risks:
                subtitle += '  |  ' + ', '.join(risks)

            # Tickets honey ganham linha vermelha também, pra chamar atenção.
            kind = 'critical' if 'HONEY' in risks else 'ticket'
            cf = CollapsibleFrame(parent, title=f'Ticket [{t.index}]',
                                  subtitle=subtitle, start_open=False,
                                  kind=kind)
            cf.pack(fill='x', pady=(6, 0), padx=(12, 0))

            grid = ttk.Frame(cf.content)
            grid.pack(fill='x', pady=(4, 4))
            fields = [
                ('ClientName', t.client_name),
                ('ServiceRealm', t.service_realm),
                ('StartTime', t.start_time),
                ('EndTime', t.end_time),
                ('RenewTill', t.renew_till),
                ('Flags', t.flags),
                ('KeyType', t.key_type),
            ]
            for i, (k, v) in enumerate(fields):
                ttk.Label(grid, text=f'{k}:', foreground='#555',
                          font=('Segoe UI', 9)).grid(row=i, column=0,
                                                     sticky='nw', padx=(0, 8), pady=1)
                ttk.Label(grid, text=v or '-', foreground='#111',
                          font=('Consolas', 9), wraplength=860,
                          justify='left').grid(row=i, column=1, sticky='w', pady=1)

            if risks:
                rf = ttk.Frame(cf.content)
                rf.pack(fill='x', pady=(4, 0))
                ttk.Label(rf, text='Risco:', foreground='#555',
                          font=('Segoe UI', 9)).pack(side='left', padx=(0, 4))
                for rk in risks:
                    if rk == 'HONEY':
                        color = '#b71c1c'   # vermelho forte: canary
                    elif rk in ('TGT', 'TGT-Admin', 'blob_exposto'):
                        color = '#c62828'
                    elif rk in ('ok_as_delegate', 'forwardable',
                                'forwarded', 'renewable', 'pre_authent'):
                        color = '#ef6c00'
                    else:
                        color = '#2e7d32'
                    ttk.Label(rf, text=f'[{rk}]',
                              foreground=color).pack(side='left', padx=3)

            bf = ttk.Frame(cf.content)
            bf.pack(fill='x', pady=(8, 0))
            ttk.Label(bf, text='Blob Kirbi:', foreground='#555',
                      font=('Segoe UI', 9)).pack(anchor='w')

            if t.blob:
                box = ttk.Frame(bf)
                box.pack(fill='x', pady=(2, 0))
                txt = tk.Text(box, height=6, wrap='char',
                              font=('Consolas', 8), bg='#fafafa')
                sb = ttk.Scrollbar(box, orient='vertical', command=txt.yview)
                txt.configure(yscrollcommand=sb.set)
                sb.pack(side='right', fill='y')
                txt.pack(side='left', fill='x', expand=True)
                txt.insert('1.0', t.blob)
                txt.configure(state='disabled')

                ttk.Button(bf, text='Copiar blob',
                           command=lambda b=t.blob: self.app.copy_to_clipboard(b)
                           ).pack(anchor='w', pady=(4, 0))
            else:
                ttk.Label(bf, text='(ausente)', foreground='#888').pack(anchor='w')
            return cf
        except Exception as e:
            print(f'[!] ticket_block: {e}')
            return None

    def _orphan_block(self, parent, blobs):
        try:
            cf = CollapsibleFrame(parent, title=f'Blobs sem ticket ({len(blobs)})',
                                  subtitle='nao associados', start_open=False,
                                  kind='ticket')
            cf.pack(fill='x', pady=(6, 0))
            for i, b in enumerate(blobs, 1):
                f = ttk.Frame(cf.content)
                f.pack(fill='x', pady=2)
                ttk.Label(f, text=f'[{i}] len={len(b)}',
                          foreground='#555', font=('Segoe UI', 9)
                          ).pack(side='left', padx=(0, 8))
                ttk.Button(f, text='Copiar',
                           command=lambda x=b: self.app.copy_to_clipboard(x)
                           ).pack(side='left')
                ttk.Label(f, text=b[:70] + '...',
                          foreground='#111', font=('Consolas', 8)
                          ).pack(side='left', padx=(8, 0))
        except Exception as e:
            print(f'[!] orphan_block: {e}')

    def _list_block(self, parent, title, items, color):
        try:
            cf = CollapsibleFrame(parent, title=f'{title} ({len(items)})',
                                  subtitle='', start_open=False, kind='ticket')
            cf.pack(fill='x', pady=(6, 0))
            for item in items:
                ttk.Label(cf.content, text=f'- {item}', wraplength=1000,
                          justify='left', foreground=color
                          ).pack(anchor='w', pady=1)
        except Exception as e:
            print(f'[!] list_block: {e}')

    # ---- filtro / expand-all / export ----
    def _apply_filter(self):
        """Esconde users cujo texto não bate; se bate no ticket, mantém o user."""
        try:
            q = (self._filter_var.get() if self._filter_var else '').strip().lower()
            if not q:
                self._clear_filter(reset_entry=False)
                return
            for u, ucf, tframes in self._user_frames:
                user_hay = ' '.join(filter(None, [
                    u.user_name, u.domain, u.upn, u.user_sid,
                    u.auth_package, u.logon_server,
                ])).lower()
                user_hit = q in user_hay
                any_tkt_hit = False
                for t, tcf in tframes:
                    tkt_hay = ' '.join(filter(None, [
                        t.client_name, t.service_realm, t.flags, t.key_type,
                    ])).lower()
                    tkt_hit = q in tkt_hay
                    tcf.set_visible(user_hit or tkt_hit)
                    any_tkt_hit = any_tkt_hit or tkt_hit
                ucf.set_visible(user_hit or any_tkt_hit)
        except Exception as e:
            print(f'[!] filter: {e}')

    def _clear_filter(self, reset_entry: bool = True):
        try:
            if reset_entry and self._filter_var is not None:
                self._filter_var.set('')
            for u, ucf, tframes in self._user_frames:
                ucf.set_visible(True)
                for t, tcf in tframes:
                    tcf.set_visible(True)
        except Exception as e:
            print(f'[!] clear_filter: {e}')

    def _set_all_expanded(self, expanded: bool):
        try:
            for u, ucf, tframes in self._user_frames:
                ucf.set_expanded(expanded)
                for t, tcf in tframes:
                    tcf.set_expanded(expanded)
        except Exception as e:
            print(f'[!] set_all_expanded: {e}')

    def _export_json(self):
        try:
            default_name = os.path.splitext(os.path.basename(self.path))[0] + '.json'
            out = filedialog.asksaveasfilename(
                title='Exportar dump parseado',
                defaultextension='.json',
                initialfile=default_name,
                filetypes=[('JSON', '*.json'), ('Todos', '*.*')],
            )
            if not out:
                return
            payload = asdict(self.result)
            payload['_source_path'] = self.path
            with open(out, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            self.app.status_var.set(f'Exportado: {out}')
        except Exception as e:
            messagebox.showerror('Erro', f'Falha ao exportar JSON:\n{e}')

    def _user_risk(self, u: UserEntry) -> str:
        try:
            tags = set()
            # Detecção de alto privilégio: RID well-known.
            sid = (u.user_sid or '')
            rid = sid.rsplit('-', 1)[-1] if '-' in sid else ''
            priv_label = HIGH_PRIV_RIDS.get(rid)

            for t in u.tickets:
                if (t.service_realm or '').lower().startswith('krbtgt/'):
                    if priv_label:
                        tags.add(f'TGT-{priv_label}')
                    elif 'administrator' in (u.user_name or '').lower():
                        tags.add('TGT-Admin')
                    else:
                        tags.add('TGT')
                if is_honey_ticket(t):
                    tags.add('HONEY')
            if is_honey_user(u):
                tags.add('HONEY-USER')
            return ', '.join(sorted(tags))
        except Exception:
            return ''


# ---------------------------------------------------------------------------
# App principal
# ---------------------------------------------------------------------------
class KrbDumpApp(tk.Tk):
    def __init__(self, initial_paths: Optional[List[str]] = None):
        super().__init__()
        self.title('Kerbeus krb_dump Viewer')
        self.geometry('1200x820')
        self.minsize(860, 540)

        self.paths: List[str] = []
        self.tabs: dict = {}

        self._setup_styles()
        self._build_ui()

        for p in (initial_paths or []):
            self.after(100, lambda path=p: self._add_file(path))

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TFrame', background='#f5f5f5')
        style.configure('TLabel', background='#f5f5f5')

    def _build_ui(self):
        top = ttk.Frame(self, padding=(8, 6))
        top.pack(fill='x')
        ttk.Button(top, text='+ Adicionar arquivo(s)...',
                   command=self._browse_files).pack(side='left')
        ttk.Button(top, text='+ Adicionar diretorio...',
                   command=self._browse_dir).pack(side='left', padx=(6, 0))
        ttk.Button(top, text='Recarregar aba',
                   command=self._reload_current).pack(side='left', padx=(6, 0))
        ttk.Button(top, text='Fechar aba',
                   command=self._close_current).pack(side='left', padx=(6, 0))
        ttk.Button(top, text='Fechar todas',
                   command=self._close_all).pack(side='left', padx=(6, 0))

        self.status_var = tk.StringVar(value='Adicione um arquivo ou diretorio de dumps.')
        ttk.Label(self, textvariable=self.status_var, padding=(8, 2),
                  relief='sunken').pack(side='bottom', fill='x')

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=8, pady=(4, 4))
        self.notebook.bind('<Button-3>', self._on_tab_right_click)
        self.notebook.bind('<Button-2>', self._on_middle_click)

        self._placeholder_tab: Optional[ttk.Frame] = None
        self._show_placeholder()

        self.bind_all('<MouseWheel>', self._on_wheel)

    # ---- placeholder ----
    def _show_placeholder(self):
        try:
            if self.tabs:
                return
            if self._placeholder_tab is not None:
                try:
                    if self._placeholder_tab.winfo_exists():
                        self.notebook.forget(self._placeholder_tab)
                        self._placeholder_tab.destroy()
                except Exception:
                    pass
                self._placeholder_tab = None

            ph = ttk.Frame(self.notebook)
            ttk.Label(ph,
                      text='Nenhum arquivo carregado.\n\n'
                           'Clique em "+ Adicionar arquivo(s)..." ou\n'
                           '"+ Adicionar diretorio..." para comecar.',
                      font=('Segoe UI', 12), foreground='#888',
                      justify='center').pack(expand=True)
            self.notebook.add(ph, text='(vazio)')
            self._placeholder_tab = ph
        except Exception as e:
            print(f'[!] placeholder: {e}')

    # ---- adicionar / remover ----
    def _add_file(self, path: str):
        try:
            path = os.path.abspath(path)
        except Exception:
            pass
        if path in self.tabs:
            self.status_var.set(f'Arquivo ja carregado: {path}')
            return

        try:
            result = parse_file(path)
        except FileNotFoundError:
            messagebox.showerror('Erro', f'Nao encontrado:\n{path}')
            return
        except PermissionError:
            messagebox.showerror('Erro', f'Sem permissao:\n{path}')
            return
        except Exception as e:
            messagebox.showerror('Erro', f'Falha ao ler:\n{path}\n\n{e}')
            return

        if self._placeholder_tab is not None and self._placeholder_tab.winfo_exists():
            try:
                self.notebook.forget(self._placeholder_tab)
                self._placeholder_tab.destroy()
            except Exception:
                pass
            self._placeholder_tab = None

        tab = FileTab(self.notebook, self, path, result)
        label = os.path.basename(path) or path
        existing = [self.notebook.tab(t, 'text') for t in self.notebook.tabs()]
        if label in existing:
            parent = os.path.basename(os.path.dirname(path))
            label = f'{parent}/{label}'
            n = 2
            while label in existing:
                label = f'{parent}/{os.path.basename(path)} ({n})'
                n += 1

        self.notebook.add(tab, text=label)
        self.tabs[path] = tab
        self.paths.append(path)
        self.notebook.select(tab)
        self._update_status()

    def _browse_files(self):
        try:
            paths = filedialog.askopenfilenames(
                title='Selecionar dump(s) krb_dump',
                filetypes=[('Dumps', '*.txt *.log *.dump'),
                           ('Texto', '*.txt'),
                           ('Todos', '*.*')]
            )
            for p in paths:
                self._add_file(p)
        except Exception as e:
            messagebox.showerror('Erro', f'Falha no dialogo: {e}')

    def _browse_dir(self):
        try:
            folder = filedialog.askdirectory(
                title='Selecionar diretorio com dumps'
            )
            if not folder:
                return
            files, warns = expand_input_paths([folder])
            if not files:
                messagebox.showwarning(
                    'Aviso',
                    f'Nenhum dump encontrado em:\n{folder}\n\n'
                    f'Extensoes aceitas: {", ".join(DUMP_EXTENSIONS)} '
                    f'(ou sem extensao).'
                )
                return
            for p in files:
                self._add_file(p)
            if warns:
                self.status_var.set(
                    f'{len(files)} arquivo(s) do diretorio  |  {len(warns)} aviso(s)')
        except Exception as e:
            messagebox.showerror('Erro', f'Falha ao adicionar diretorio: {e}')

    def _current_tab(self) -> Optional[FileTab]:
        try:
            current = self.notebook.select()
            if not current:
                return None
            w = self.notebook.nametowidget(current)
            return w if isinstance(w, FileTab) else None
        except Exception:
            return None

    def _reload_current(self):
        tab = self._current_tab()
        if tab is None:
            self.status_var.set('Nenhuma aba de arquivo selecionada.')
            return
        path = tab.path
        self._remove_tab(tab)
        self._add_file(path)

    def _close_current(self):
        tab = self._current_tab()
        if tab is None:
            self.status_var.set('Nenhuma aba de arquivo selecionada.')
            return
        self._remove_tab(tab)

    def _close_all(self):
        for path in list(self.tabs.keys()):
            tab = self.tabs.get(path)
            if tab is None:
                continue
            try:
                self.notebook.forget(tab)
                tab.destroy()
            except Exception:
                pass
        self.tabs.clear()
        self.paths.clear()
        self._show_placeholder()
        self._update_status()

    def _remove_tab(self, tab):
        try:
            if tab is self._placeholder_tab:
                return
            for path, t in list(self.tabs.items()):
                if t is tab:
                    self.notebook.forget(tab)
                    tab.destroy()
                    del self.tabs[path]
                    try:
                        self.paths.remove(path)
                    except ValueError:
                        pass
                    break
            if not self.tabs:
                self._show_placeholder()
            self._update_status()
        except Exception as e:
            print(f'[!] remove_tab: {e}')

    # ---- click handlers ----
    def _on_tab_right_click(self, event):
        try:
            idx = self.notebook.index(f'@{event.x},{event.y}')
            tab_id = self.notebook.tabs()[idx]
            tab = self.notebook.nametowidget(tab_id)
            if not isinstance(tab, FileTab):
                return
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label='Recarregar',
                             command=lambda: (self._remove_tab(tab),
                                              self._add_file(tab.path)))
            menu.add_command(label='Fechar esta aba',
                             command=lambda: self._remove_tab(tab))
            menu.add_separator()
            menu.add_command(label='Fechar todas', command=self._close_all)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        except Exception:
            pass

    def _on_middle_click(self, event):
        try:
            idx = self.notebook.index(f'@{event.x},{event.y}')
            tab = self.notebook.nametowidget(self.notebook.tabs()[idx])
            if isinstance(tab, FileTab):
                self._remove_tab(tab)
        except Exception:
            pass

    def _on_wheel(self, event):
        try:
            w = self.winfo_containing(event.x_root, event.y_root)
            while w is not None:
                if isinstance(w, ScrollableFrame):
                    w.scroll_by(event.delta)
                    return
                w = getattr(w, 'master', None)
        except Exception:
            pass

    # ---- util ----
    def _update_status(self):
        try:
            n_files = len(self.tabs)
            n_users = sum(len(t.result.users) for t in self.tabs.values())
            n_tickets = sum(sum(len(u.tickets) for u in t.result.users)
                            for t in self.tabs.values())
            n_warnings = sum(len(t.result.warnings) for t in self.tabs.values())
            n_errors = sum(len(t.result.errors) for t in self.tabs.values())
            self.status_var.set(
                f'{n_files} arquivo(s)  |  {n_users} usuario(s)  |  '
                f'{n_tickets} ticket(s)  |  {n_warnings} aviso(s)  |  '
                f'{n_errors} erro(s)'
            )
        except Exception:
            pass

    def copy_to_clipboard(self, text):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_var.set('Copiado para a area de transferencia.')
        except Exception as e:
            messagebox.showerror('Erro', f'Falha ao copiar: {e}')


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    raw_args = sys.argv[1:]

    files, warns = expand_input_paths(raw_args)

    if raw_args and not files:
        print('[!] nenhum arquivo encontrado nos caminhos informados:', file=sys.stderr)
        for w in warns:
            print(f'  - {w}', file=sys.stderr)

    try:
        app = KrbDumpApp(initial_paths=files)
        if warns:
            app.after(400, lambda: app.status_var.set(
                f'{len(files)} arquivo(s) carregado(s)  |  '
                f'{len(warns)} aviso(s) de caminho'))
        app.mainloop()
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f'[!] erro fatal: {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())