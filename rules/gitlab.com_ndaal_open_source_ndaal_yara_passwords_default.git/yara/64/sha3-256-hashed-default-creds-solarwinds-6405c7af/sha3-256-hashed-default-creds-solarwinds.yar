rule sha3_256_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4af2f1e83fd909b903dec03d40102b487656c60cf799bd79f63f91ecc7f9f05b"
    $a1="13b61e204b469cffdac27703d8f4904b49ad8b88d2b4457bc39f02a3b7efa336"
    $a2="209262095ad0e1d886b2fbb50819a5f4e7dcc0658841893b88e86ba222a2b0ee"
    $a3="209262095ad0e1d886b2fbb50819a5f4e7dcc0658841893b88e86ba222a2b0ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}