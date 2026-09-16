rule md5_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5d7cffe25654f7e3a1e334118c71549"
    $a1="00fcdb931d4ffe7fe44fb306171bfe04"
    $a2="e5d7cffe25654f7e3a1e334118c71549"
    $a3="997ea2dea48524ac630e4ce0385264d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}