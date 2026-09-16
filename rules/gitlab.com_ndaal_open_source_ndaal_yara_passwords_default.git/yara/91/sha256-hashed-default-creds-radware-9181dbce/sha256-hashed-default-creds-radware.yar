rule sha256_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8cac552ef22e00eedd1f54b5a6e735ff57d093eac889aad542dda57c585d01c"
    $a1="d8cac552ef22e00eedd1f54b5a6e735ff57d093eac889aad542dda57c585d01c"
    $a2="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
    $a3="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}