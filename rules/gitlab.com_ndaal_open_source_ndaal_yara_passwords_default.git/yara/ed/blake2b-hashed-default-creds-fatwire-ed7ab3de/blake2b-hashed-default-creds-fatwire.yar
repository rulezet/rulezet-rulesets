rule blake2b_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7862c897f79175838edadbb5d7d2e84808a9160bbd26e33f96e0fb95b6a9f6e8a453ec25eb5e0315071a0422bc406003bcb678f931c53a91a9732ac4958b01b7"
    $a1="7862c897f79175838edadbb5d7d2e84808a9160bbd26e33f96e0fb95b6a9f6e8a453ec25eb5e0315071a0422bc406003bcb678f931c53a91a9732ac4958b01b7"
    $a2="ceef08f04fee77d263b2a6ecbd96aafdda48016f24e45584ec648be3828795e87185ba2047cdb9460c122156efc40dddf06be8706d53ce47423f868649c3e796"
    $a3="ae615d73902ba18d0d7454ab20deeacf4c6f95d07674a442a307ee932feb8eec3a9c61176ef2a4797951cdb2905bbd851185ab75890f613456516ba946d2c88b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}