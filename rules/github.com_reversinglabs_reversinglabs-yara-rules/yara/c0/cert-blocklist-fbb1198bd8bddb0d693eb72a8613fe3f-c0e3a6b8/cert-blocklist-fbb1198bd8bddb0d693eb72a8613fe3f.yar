import "pe"
rule cert_blocklist_fbb1198bd8bddb0d693eb72a8613fe3f {
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
            pe.signatures[i].subject contains "Trade Hunters, s. r. o." and (
                pe.signatures[i].serial == "00:fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f" or
                pe.signatures[i].serial == "fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}