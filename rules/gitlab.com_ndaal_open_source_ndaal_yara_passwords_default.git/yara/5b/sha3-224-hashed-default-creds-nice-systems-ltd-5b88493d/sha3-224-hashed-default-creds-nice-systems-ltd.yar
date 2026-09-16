rule sha3_224_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f515cb98b43ae1365b6e23e61e366ac8889b35beef0ce471e5d96d8c"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="f515cb98b43ae1365b6e23e61e366ac8889b35beef0ce471e5d96d8c"
    $a3="353bdc81856e051f5aa1d1ebd9ed11691ba9cee08496778ed197b55b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}