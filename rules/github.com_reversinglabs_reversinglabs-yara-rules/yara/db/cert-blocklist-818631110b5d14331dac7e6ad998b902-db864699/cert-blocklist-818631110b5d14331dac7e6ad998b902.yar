import "pe"
rule cert_blocklist_818631110b5d14331dac7e6ad998b902 {
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
            pe.signatures[i].subject contains "2 TOY GUYS LLC" and (
                pe.signatures[i].serial == "00:81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02" or
                pe.signatures[i].serial == "81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02"
            ) and
            1571616000 <= pe.signatures[i].not_after
        )
}