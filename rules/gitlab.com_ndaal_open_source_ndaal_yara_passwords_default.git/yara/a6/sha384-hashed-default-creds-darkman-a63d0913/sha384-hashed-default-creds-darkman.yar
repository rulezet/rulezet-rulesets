rule sha384_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37ea15be066e1403e294d8a989ee2def70adbc014f70c1e5894a52295c10d0127317a4344ef29f4d49a03838682fbb3e"
    $a1="37ea15be066e1403e294d8a989ee2def70adbc014f70c1e5894a52295c10d0127317a4344ef29f4d49a03838682fbb3e"
condition:
    ($a0 and $a1)
}