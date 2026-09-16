rule sha512_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="546041c1bb85813fc72b061f6aabbfe7b58635391490b1f4b3e9f260c1531aa2913b765ace1969608228f7c54b356c2085173cfe86adc97c6948eac7f6b9828d"
    $a1="2e82a0b12edbc1de6a225de1c542586a356c539fd4208f230cc7302cc5c3107a87659dff8b3a0097396389acebc3c6401b962509464a6b7bef82bccf3f274550"
condition:
    ($a0 and $a1)
}