import "pe"
rule cert_blocklist_fbb96a90b6718810311767ca25ab1e48 {
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
            pe.signatures[i].subject contains "Rakurs LLC" and (
                pe.signatures[i].serial == "00:fb:b9:6a:90:b6:71:88:10:31:17:67:ca:25:ab:1e:48" or
                pe.signatures[i].serial == "fb:b9:6a:90:b6:71:88:10:31:17:67:ca:25:ab:1e:48"
            ) and
            1636046757 <= pe.signatures[i].not_after
        )
}