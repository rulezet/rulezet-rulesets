rule nthash_hashed_default_creds_axis_communications
{
    meta:
        id = "1MnBH5yjkbhfUi9TkD5qE7"
        fingerprint = "fec26e54c9af3d0053622638ec5c61d694ca09ad691c0a7bcc03c91b6a6476ff"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for axis_communications."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36aa83bdcab3c9fdaf321ca42a31c3fc"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}