rule sha256_hashed_default_creds_globespan_virata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for globespan_virata."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61e06ee14cc6e7629a9e82a6d97eddf683d14f90c7e46f10d46981e437f7699b"
    $a1="61e06ee14cc6e7629a9e82a6d97eddf683d14f90c7e46f10d46981e437f7699b"
condition:
    ($a0 and $a1)
}