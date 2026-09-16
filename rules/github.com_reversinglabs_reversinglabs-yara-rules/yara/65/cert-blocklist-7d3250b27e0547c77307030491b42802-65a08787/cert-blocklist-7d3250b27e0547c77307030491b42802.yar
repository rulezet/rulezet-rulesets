import "pe"
rule cert_blocklist_7d3250b27e0547c77307030491b42802 {
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
            pe.signatures[i].subject contains "Banco do Brasil S.A." and
            pe.signatures[i].serial == "7d:32:50:b2:7e:05:47:c7:73:07:03:04:91:b4:28:02" and
            1412207999 <= pe.signatures[i].not_after
        )
}