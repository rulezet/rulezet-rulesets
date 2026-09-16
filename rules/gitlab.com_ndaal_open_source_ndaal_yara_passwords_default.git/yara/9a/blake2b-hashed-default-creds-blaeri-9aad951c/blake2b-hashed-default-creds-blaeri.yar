rule blake2b_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25f6a4deb4df829aa8b18ba2dcdaa905a9f708afb8897acd67780bf14727f5d5c41e7b061d62620c450332d02dcbb0555a2f940052cb5b734cf388a533138e28"
    $a1="087f2a0c3e81a71ce032eaeaceb67f598cb3f6fe40450544f95609d591c28026813a1046e040629c410e0d7b08b60a0a94993239fea0bb913f13bf8e32b1ad37"
condition:
    ($a0 and $a1)
}