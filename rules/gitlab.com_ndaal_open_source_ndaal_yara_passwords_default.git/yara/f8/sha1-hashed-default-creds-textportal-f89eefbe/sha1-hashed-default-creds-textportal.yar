rule sha1_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb2237d0679ca88db6464eac60da96345513964"
    $a1="08d28b00d8c2c1ce4d0662857db53c8191ad24a5"
    $a2="8cb2237d0679ca88db6464eac60da96345513964"
    $a3="53ca4cbc4293ab95b055ea35baf3200a80358326"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}