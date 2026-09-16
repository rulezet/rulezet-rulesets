import "pe"
rule cert_blocklist_0e808f231515bc519eea1a73cdf3266f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Careto malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TecSystem Ltd." and
            pe.signatures[i].serial == "0e:80:8f:23:15:15:bc:51:9e:ea:1a:73:cd:f3:26:6f" and
            1468799999 <= pe.signatures[i].not_after
        )
}