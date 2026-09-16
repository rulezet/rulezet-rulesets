rule blake2b_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a1="45817fa4dacf4e18290b58789369bc64756270058b4426c3b34db0ede8c6a7fb900ca0a580cc5a8f8d81e77669bfa8803d289fe046bfdac0e8bb89074d9d0f4f"
condition:
    ($a0 and $a1)
}