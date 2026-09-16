rule sha512_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47ec0b882ceb3b00906576bf0c7b9ff11684a48cd4fb4241412461b11ca620311cc667edd9b9af868e945ad66ffdfc880f6db2ec71102becaf410088ee46a67d"
    $a1="6bbd8cf74e7727ae177dc83a74f957c9f5f4f24d06d8b51bfce6f39080cccd64f83cdfcfe1bff45666463298a9f382185b892b8cb658fba894eab90c94f9d544"
condition:
    ($a0 and $a1)
}