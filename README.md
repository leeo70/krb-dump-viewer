# krb-dump-viewer

A small Tkinter GUI to triage [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) `krb_dump` output
when it comes back as a wall of text from your C2 (Cobalt Strike, Havoc, Sliver, etc).

Users become collapsible blocks. Tickets inside each user become their own
collapsible blocks. Risk tags (TGT, forwardable, pre_authent, honey, blob
exposure) are computed and colored so you can skim a 200-ticket dump in
seconds and find the one TGT that matters.

No external dependencies. `tkinter` ships with Python.

## Features

- Multi-file / multi-tab. Drop a whole folder of dumps and compare side by side.
- Collapsible per-user and per-ticket blocks. Red highlight for high-privilege
  TGTs (RID 500 / 512 / 518 / 519) and honey matches.
- Risk tagging: `TGT`, `TGT-DomainAdmins`, `TGT-EnterpriseAdmins`,
  `forwardable`, `forwarded`, `renewable`, `pre_authent`, `ok_as_delegate`,
  `HONEY`, `blob_exposto` / `sem_blob`.
- Honey / decoy detection via a configurable `HONEY_PATTERNS` tuple at the top
  of the script. Edit it to match your target (sample SPN patterns, decoy
  user names, canary accounts).
- Live filter box: hides users / tickets that do not match the search text.
  Searches user name, domain, UPN, SID, auth package, logon server, client
  name, service realm, flags, key type.
- "Expand all" / "Collapse all" buttons.
- "Copy blob" button on each ticket to paste the base64 kirbi into Rubeus
  / Kerbeus `krb_ptt`.
- "Export JSON" dumps the parsed structure for scripting (feed another tool,
  diff two dumps, pick targets automatically).
- Base64 KRB-CRED detection accepts `doI`, `doH`, `doJ`, `MII` prefixes.

## Install

```bash
git clone https://github.com/leeo70/krb-dump-viewer.git
cd krb-dump-viewer
python krb_dump_viewer.py samples/
```

Tested on Python 3.10+ on Windows 10 / 11. Should run on any OS with Tk.

## Usage

```bash
python krb_dump_viewer.py                       # empty, open from UI
python krb_dump_viewer.py dump1.txt dump2.txt   # individual files
python krb_dump_viewer.py .\dumps\              # all dumps in a folder
python krb_dump_viewer.py .\dumps\ .\other\     # several folders
python krb_dump_viewer.py .\dumps\ .\dump.txt   # mixed
```

Accepted extensions: `.txt`, `.log`, `.dump`, and files with no extension.
Right-click a tab for reload / close / close-all. Middle-click a tab closes it.

## Expected input format

The viewer parses the text that Kerbeus-BOF prints when you run `krb_dump` or
`krb_triage` and dump the beacon output. Minimal shape:

```
Kerbeus DUMP by ...
Action: ...

UserName              : Administrator
Domain                : CONTOSO
LogonId               : 0x3e7
UserSID               : S-1-5-18
Authentication package: Kerberos
LogonServer           : DC01
UserPrincipalName     : Administrator@contoso.com

[*] Cached tickets: (2)

  [0]
    ClientName       : Administrator @ CONTOSO.COM
    ServiceRealm     : krbtgt/CONTOSO.COM @ CONTOSO.COM
    StartTime (UTC)  : ...
    EndTime (UTC)    : ...
    RenewTill (UTC)  : ...
    Flags            : forwardable, renewable, pre_authent
    KeyType          : aes256_cts_hmac_sha1

doIE...base64...kirbi...blob...
```

A full example lives in [`samples/example.txt`](samples/example.txt).

## Configuring honey detection

Open `krb_dump_viewer.py` and edit the `HONEY_PATTERNS` tuple near the top:

```python
HONEY_PATTERNS: tuple = (
    'honeysvc/',
    'canary_user_samaccountname',
    'mssqlsvc/host-that-does-not-exist',
)
```

Any ticket whose `client_name` or `service_realm` contains one of these
substrings (case-insensitive) is flagged `HONEY` in red and the user block
turns red too. This is purely a client-side heuristic to keep you from
touching decoy accounts.

## Export JSON schema

The "Export JSON" button serializes the full `ParseResult` dataclass. Shape:

```json
{
  "tool_header": "Kerbeus DUMP by ...",
  "action": "...",
  "users": [
    {
      "user_name": "Administrator",
      "domain": "CONTOSO",
      "logon_id": "0x3e7",
      "user_sid": "S-1-5-18",
      "upn": "Administrator@contoso.com",
      "tickets_declared": 2,
      "tickets": [
        {
          "index": 0,
          "client_name": "Administrator @ CONTOSO.COM",
          "service_realm": "krbtgt/CONTOSO.COM @ CONTOSO.COM",
          "flags": "forwardable, renewable, pre_authent",
          "key_type": "aes256_cts_hmac_sha1",
          "blob": "doIE..."
        }
      ]
    }
  ],
  "orphan_blobs": [],
  "warnings": [],
  "errors": [],
  "_source_path": "C:\\dumps\\dump1.txt"
}
```

## Not in scope

- Parsing kirbi blobs natively. Use Rubeus / Kerbeus for that; this viewer
  gives you the base64 to pipe in.
- Writing anything back. The viewer is read-only and never touches the
  original dump file.
- Fancy themes. One Tk theme (`clam`), two accent colors. On purpose.

## License

MIT. See [`LICENSE`](LICENSE).
