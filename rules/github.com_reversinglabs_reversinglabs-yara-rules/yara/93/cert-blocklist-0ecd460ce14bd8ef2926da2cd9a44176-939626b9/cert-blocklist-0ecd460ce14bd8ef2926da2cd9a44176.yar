import "pe"
rule cert_blocklist_0ecd460ce14bd8ef2926da2cd9a44176 {
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
            pe.signatures[i].subject contains "Rabah Azrarak" and
            pe.signatures[i].serial == "0e:cd:46:0c:e1:4b:d8:ef:29:26:da:2c:d9:a4:41:76" and
            1463035153 <= pe.signatures[i].not_after
        )
}