rule nthash_hashed_default_creds_zyxel_nwa_nap_wac_wireless_access_point_series_ftp
{
    meta:
        id = "6OqVvQcLA2lvIiu1vhSHyI"
        fingerprint = "3f2fe0e238717f8ae77856e53e7829dfd49b7ddbe0117667a07ef122b79867b4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_nwa_nap_wac_wireless_access_point_series_ftp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="9d3a8358d2e575f22c57f9424e80ec1a"
condition:
    ($a0 and $a1)
}