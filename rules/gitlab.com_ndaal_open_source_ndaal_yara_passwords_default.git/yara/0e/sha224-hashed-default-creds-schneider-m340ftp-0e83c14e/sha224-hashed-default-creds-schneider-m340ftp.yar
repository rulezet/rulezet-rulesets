rule sha224_hashed_default_creds_schneider_m340ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340ftp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee2d93e39d51298022af4b5d1df8a3be22a455beb4bb3e18c539d0bb"
    $a1="f308d01316af4e6b9b0a766f5b328f00723fdc1b97c2859f07bb1114"
condition:
    ($a0 and $a1)
}