import "pe"
rule cert_blocklist_029685cda1c8233d2409a31206f78f9f {
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
            pe.signatures[i].subject contains "KOTO TRADE, dru\\xC5\\xBEba za posredovanje, d.o.o." and
            pe.signatures[i].serial == "02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f" and
            1612396800 <= pe.signatures[i].not_after
        )
}