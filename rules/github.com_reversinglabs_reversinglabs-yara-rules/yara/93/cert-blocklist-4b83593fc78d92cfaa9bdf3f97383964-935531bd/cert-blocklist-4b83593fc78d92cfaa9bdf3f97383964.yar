import "pe"
rule cert_blocklist_4b83593fc78d92cfaa9bdf3f97383964 {
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
            pe.signatures[i].subject contains "OOO Kometa" and
            pe.signatures[i].serial == "4b:83:59:3f:c7:8d:92:cf:aa:9b:df:3f:97:38:39:64" and
            1579996800 <= pe.signatures[i].not_after
        )
}