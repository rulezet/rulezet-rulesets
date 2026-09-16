import "pe"
rule cert_blocklist_9813229efe0046d23542cc7569d5a403 {
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
            pe.signatures[i].subject contains "OOO \"MPS\"" and (
                pe.signatures[i].serial == "00:98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03" or
                pe.signatures[i].serial == "98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03"
            ) and
            1575849600 <= pe.signatures[i].not_after
        )
}