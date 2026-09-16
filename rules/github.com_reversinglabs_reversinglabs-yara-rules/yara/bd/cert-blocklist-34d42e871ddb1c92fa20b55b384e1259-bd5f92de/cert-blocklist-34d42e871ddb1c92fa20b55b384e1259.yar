import "pe"
rule cert_blocklist_34d42e871ddb1c92fa20b55b384e1259 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VENS CORP" and
            pe.signatures[i].serial == "34:d4:2e:87:1d:db:1c:92:fa:20:b5:5b:38:4e:12:59" and
            1630368000 <= pe.signatures[i].not_after
        )
}