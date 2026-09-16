import "pe"
rule cert_blocklist_0a82bd1e144e8814d75b1a5527bebf3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA G2" and
            pe.signatures[i].serial == "0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e" and
            1308182400 <= pe.signatures[i].not_after
        )
}