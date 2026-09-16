rule blake2b_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b2afcc33b786e8aedf84d5372c0be59329905e546e837445eaaf75c0dd46aaceaed28931df310a441e44ede45df5c9c8a631240570a44be53beacaa37da20f4"
    $a1="953356f07bcfd347bcd4df72861aa54771c87947526ab5ea7b1c5f9676e436e0c46984591883647cd9fc2dbf68388935bafd5c34d54e52e69a854da431cdd952"
    $a2="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a3="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}