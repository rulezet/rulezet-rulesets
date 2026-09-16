rule nthash_hashed_default_creds_network_associates
{
    meta:
        id = "3U4C5v5H7gq9onWtvmTcRU"
        fingerprint = "a93bbbbf3db231828d2d29c4de5dc77dc0916604284b769d85ba7c44c7c870aa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc9294535d820b3d49b89dff6be4a382"
    $a1="686219ea12a26a1e267f950eb1ae2f3e"
    $a2="70d9ff937743c09b7f5ba58d2582c944"
    $a3="00dc2024f0c89783051855cd566c8522"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}