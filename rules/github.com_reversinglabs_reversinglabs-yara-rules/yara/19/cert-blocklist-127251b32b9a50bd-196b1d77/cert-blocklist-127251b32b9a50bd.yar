import "pe"
rule cert_blocklist_127251b32b9a50bd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing OSX DokSpy backdoor."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Developer ID Application: Edouard Roulet (W7J9LRHXTG)" and
            pe.signatures[i].serial == "12:72:51:b3:2b:9a:50:bd" and
            1493769599 <= pe.signatures[i].not_after
        )
}