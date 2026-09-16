import "pe"
rule cert_blocklist_0fbc30db127a536c34d7a0fa81b48193 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Megabit, OOO" and
            pe.signatures[i].serial == "0f:bc:30:db:12:7a:53:6c:34:d7:a0:fa:81:b4:81:93" and
            1466121599 <= pe.signatures[i].not_after
        )
}