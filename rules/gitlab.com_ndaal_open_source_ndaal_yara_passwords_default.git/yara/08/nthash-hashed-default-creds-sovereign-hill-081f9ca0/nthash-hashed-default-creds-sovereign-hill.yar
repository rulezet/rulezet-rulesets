rule nthash_hashed_default_creds_sovereign_hill
{
    meta:
        id = "mqs6w9mWmbWl2LbMYnNFv"
        fingerprint = "d6035904a8bdbe9dcc9891b9a40cc1b6d9d39adf6c48eabb64d648c933d8222a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sovereign_hill."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4c37a44c7168162866a386121b48136"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}