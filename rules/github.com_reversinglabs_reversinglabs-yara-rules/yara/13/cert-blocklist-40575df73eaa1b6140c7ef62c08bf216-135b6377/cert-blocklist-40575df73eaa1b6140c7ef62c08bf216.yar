import "pe"
rule cert_blocklist_40575df73eaa1b6140c7ef62c08bf216 {
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
            pe.signatures[i].subject contains "Dali Feifang Tech Co.,LTD." and
            pe.signatures[i].serial == "40:57:5d:f7:3e:aa:1b:61:40:c7:ef:62:c0:8b:f2:16" and
            1394063999 <= pe.signatures[i].not_after
        )
}