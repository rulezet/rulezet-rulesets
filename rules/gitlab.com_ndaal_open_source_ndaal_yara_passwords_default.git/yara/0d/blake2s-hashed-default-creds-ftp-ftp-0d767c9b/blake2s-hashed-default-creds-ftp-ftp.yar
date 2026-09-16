rule blake2s_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="238041a05ef5fb96bbffd6c5de66310bbf24d41406a2305189936e935ed91505"
    $a1="238041a05ef5fb96bbffd6c5de66310bbf24d41406a2305189936e935ed91505"
    $a2="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a3="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}