import "pe"
rule cert_blocklist_01e2b4f759811c64379fca0be76d2dce {
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
            pe.signatures[i].subject contains "Sony Pictures Entertainment Inc." and
            pe.signatures[i].serial == "01:e2:b4:f7:59:81:1c:64:37:9f:ca:0b:e7:6d:2d:ce" and
            1417651200 <= pe.signatures[i].not_after
        )
}