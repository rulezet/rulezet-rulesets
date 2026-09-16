import "pe"
rule cert_blocklist_191322a00200f793 {
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
            pe.signatures[i].subject contains "PRABHAKAR NARAYAN" and
            pe.signatures[i].serial == "19:13:22:a0:02:00:f7:93" and
            1442966399 <= pe.signatures[i].not_after
        )
}