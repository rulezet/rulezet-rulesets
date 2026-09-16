rule nthash_hashed_default_creds_alcatel_newbridge_timestep
{
    meta:
        id = "1lb1QOKcwEkA17vZ9hoG4I"
        fingerprint = "1849ca3adbafd9ad308acbeb930e98111c3296f748aa81192295bd371faa91af"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alcatel_newbridge_timestep."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="719e6e9d90ec1272f1c3e4120b714064"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}