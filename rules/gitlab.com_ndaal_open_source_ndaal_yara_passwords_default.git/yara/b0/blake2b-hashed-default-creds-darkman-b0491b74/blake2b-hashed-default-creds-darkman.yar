rule blake2b_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="539a05d51f92cb8a08d531414c69a83480fe8012954da087c1d21541dc1006de7dfb25de1b581fb791c12ba30316e68224b81b36df743fd7442d460e8bf8c0b9"
    $a1="539a05d51f92cb8a08d531414c69a83480fe8012954da087c1d21541dc1006de7dfb25de1b581fb791c12ba30316e68224b81b36df743fd7442d460e8bf8c0b9"
condition:
    ($a0 and $a1)
}