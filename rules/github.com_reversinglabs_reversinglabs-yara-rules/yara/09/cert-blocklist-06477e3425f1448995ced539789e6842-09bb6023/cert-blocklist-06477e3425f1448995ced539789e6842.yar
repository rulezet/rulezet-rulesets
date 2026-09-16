import "pe"
rule cert_blocklist_06477e3425f1448995ced539789e6842 {
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
            pe.signatures[i].subject contains "Karim Lammali" and
            pe.signatures[i].serial == "06:47:7e:34:25:f1:44:89:95:ce:d5:39:78:9e:68:42" and
            1334275199 <= pe.signatures[i].not_after
        )
}