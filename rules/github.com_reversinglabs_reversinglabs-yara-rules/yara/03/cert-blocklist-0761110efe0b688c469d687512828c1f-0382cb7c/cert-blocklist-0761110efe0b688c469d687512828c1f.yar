import "pe"
rule cert_blocklist_0761110efe0b688c469d687512828c1f {
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
            pe.signatures[i].subject contains "ENP Games Co., Ltd." and
            pe.signatures[i].serial == "07:61:11:0e:fe:0b:68:8c:46:9d:68:75:12:82:8c:1f" and
            1433721600 <= pe.signatures[i].not_after
        )
}