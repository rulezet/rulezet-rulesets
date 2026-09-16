rule sha1_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2fe9a1420c2640eead831c10e0b6d890ee9af33"
    $a1="b521caa6e1db82e5a01c924a419870cb72b81635"
    $a2="d2fe9a1420c2640eead831c10e0b6d890ee9af33"
    $a3="42543a49c4e416a0fb7c5a7626d0d226759c3a22"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}