rule nthash_hashed_default_creds_atl
{
    meta:
        id = "2eHfokNIQ66rv7nou32liN"
        fingerprint = "1f4e4ee41f2311d28f8bc1e9a50899be1cfbd3a78991ef4e71397eca65eb81d6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d3bd16c0b87d0fe19db8ad598d778ff"
    $a1="8a68981fb3d9befdb6f440f137324546"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="e337e31aa4c614b2895ad684a51156df"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}