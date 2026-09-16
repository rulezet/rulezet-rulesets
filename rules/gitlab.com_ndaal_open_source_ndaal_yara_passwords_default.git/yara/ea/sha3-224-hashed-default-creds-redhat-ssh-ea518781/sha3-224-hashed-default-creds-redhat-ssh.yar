rule sha3_224_hashed_default_creds_redhat_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a3="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
    $a4="774057ce10e1b255cfa747982782e969231ef434a057622021ff5b9c"
    $a5="a5242831e2a4a1ad1e48fccf6c7df31b876bc86623c60394b08d5561"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}