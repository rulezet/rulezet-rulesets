import "pe"
rule cert_blocklist_7e6bc7e5a49e2c28e6f5d042 {
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
            pe.signatures[i].subject contains "Shang Hai Jian Ji Wang Luo Ke Ji You Xian Gong Si" and
            pe.signatures[i].serial == "7e:6b:c7:e5:a4:9e:2c:28:e6:f5:d0:42" and
            1560995284 <= pe.signatures[i].not_after
        )
}