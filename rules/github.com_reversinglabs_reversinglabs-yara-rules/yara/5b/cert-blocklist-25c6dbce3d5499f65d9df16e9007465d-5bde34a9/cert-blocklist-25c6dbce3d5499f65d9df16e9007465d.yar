import "pe"
rule cert_blocklist_25c6dbce3d5499f65d9df16e9007465d {
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
            pe.signatures[i].subject contains "AMCERT,LLC" and
            pe.signatures[i].serial == "25:c6:db:ce:3d:54:99:f6:5d:9d:f1:6e:90:07:46:5d" and
            1626566400 <= pe.signatures[i].not_after
        )
}