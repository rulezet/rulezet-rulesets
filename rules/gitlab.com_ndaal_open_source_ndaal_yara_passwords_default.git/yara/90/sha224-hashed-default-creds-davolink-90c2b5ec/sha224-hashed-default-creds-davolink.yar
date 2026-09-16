rule sha224_hashed_default_creds_davolink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for davolink."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a1="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
condition:
    ($a0 and $a1)
}