import "pe"
rule cert_blocklist_2b921aaaba777b5a99507196c6f1c46c {
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
            pe.signatures[i].subject contains "Python Software Foundation" and
            pe.signatures[i].serial == "2b:92:1a:aa:ba:77:7b:5a:99:50:71:96:c6:f1:c4:6c" and
            1648425600 <= pe.signatures[i].not_after
        )
}