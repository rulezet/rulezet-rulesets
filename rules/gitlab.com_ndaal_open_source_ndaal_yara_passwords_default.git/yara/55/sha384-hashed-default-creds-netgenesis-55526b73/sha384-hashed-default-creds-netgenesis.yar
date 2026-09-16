rule sha384_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6601550132597aa0d04ab201d4fa25001eadcad37853d76d9b28de1af3ba541d76911b603aa8a58f96e479b11c35119"
    $a1="a6601550132597aa0d04ab201d4fa25001eadcad37853d76d9b28de1af3ba541d76911b603aa8a58f96e479b11c35119"
condition:
    ($a0 and $a1)
}