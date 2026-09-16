rule sha3_224_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="434701fea345d9081dd8591a39d63d2bc7403c8e80364e22df00cf68"
    $a1="83740f80c57d6a793a191408301af8141887c626539cb04c192af80a"
condition:
    ($a0 and $a1)
}