rule md5_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abe6db4c9f5484fae8d79f2e868a673c"
    $a1="8a3c4c1b9018b7dd260a325e6f209a32"
    $a2="c1880c50609e9472656c8079a85af066"
    $a3="c1880c50609e9472656c8079a85af066"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}