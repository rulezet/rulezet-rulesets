import "pe"
rule cert_blocklist_44312cb9a927b4111360762b4d4bdd6d {
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
            pe.signatures[i].subject contains "BEAR ADAMS CONSULTING LIMITED" and
            pe.signatures[i].serial == "44:31:2c:b9:a9:27:b4:11:13:60:76:2b:4d:4b:dd:6d" and
            1554768000 <= pe.signatures[i].not_after
        )
}