rule sha3_384_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56fa4cfcb68c5a83273df740d3c78e7eb406aaaf35f090c46aef47721d0f2d82c80ba150e457ec35cc2a08e196f0b19d"
    $a1="da48d90385ad4b6ada027c0a243682ec89f07e4de5852ee0aa6babcabc3053386b33f92a3b0d1d5c45329fbce009ec99"
condition:
    ($a0 and $a1)
}