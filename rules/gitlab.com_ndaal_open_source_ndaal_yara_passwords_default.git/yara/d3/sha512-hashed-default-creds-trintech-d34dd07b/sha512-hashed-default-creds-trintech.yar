rule sha512_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="300ba997a1b5fac7d1591d381ac7291541e775802099043be00d9573e4955023733cbe4573782c8a2f6126415d585f6e4592710b4b8a920bf9cc16c50bd3706f"
    $a1="3c4389b521fed93a9434a46aff9d5add9f78acece5c2c3ff0e9ad5b78884d462a93eea8df86a4695697883be016d2219ad1893ce01c6d40009b27ad8196598e7"
condition:
    ($a0 and $a1)
}