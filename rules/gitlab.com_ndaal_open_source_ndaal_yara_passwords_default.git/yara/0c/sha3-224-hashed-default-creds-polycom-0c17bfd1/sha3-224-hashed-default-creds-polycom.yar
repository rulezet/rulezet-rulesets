rule sha3_224_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6908462fb4e2ce1d26de530bf014805f3f08d109f390066c635e4d0"
    $a1="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a2="89e5ca9d7cb2b3597642cd2be279676935d45af50c26dac5340930e3"
    $a3="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a4="3195faf8dac1265a29b31a6ca528f343b8209cf36b065e031b75b652"
    $a5="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a6="ba6134b813bf09cf0479742c3113f52fee1e6824feb200122c6aae95"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="cf963f34f33cf23074fa3a37d94c2455cf7b0d49be88d26d93280539"
    $a9="d27dec486e62fc697846ad373340f254a852a270db58a0e60e812a2d"
    $a10="a6908462fb4e2ce1d26de530bf014805f3f08d109f390066c635e4d0"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}