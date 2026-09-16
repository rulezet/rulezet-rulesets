rule sha3_512_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c1c9931b6af5e284fba09e79a8d408c089c9d68804403d0b0b2faab821516ed9e51419d752be8c745b9aee7b6978d5ae94560d71313597bb517096c696965f2"
    $a1="ff4059328d8431e2f675e8c874012902b6ff76b384f5eaff7c35657ac44ac9702d731372b2b1ce73f34e1247ac0822286d9aa88d0e875a72a58add8bb2f95234"
    $a2="e5b55333d7dd948adfc2f5d8b9d05f2fd41db77f35d8075be2afd0de7f54063e1d9fe8145062ff168ebb647f691a947a54c6c343735316c6a11fa1d8c8728d03"
    $a3="2b088ac0287ffe5b9183bc216d6bec09a16cde55d3e0897e20ef97af128f38f6995f5f6d19e63dafe14bbceb419314a6a1eaf5a07e3d0b7fb236450b342e41c4"
    $a4="4e83f57ac8047e43800fb4278d5c90f9252a79211c4ca8f13b445d98c831f885d00756cfcec4e09d26004f1aa910aa933fb0ec4e2426c7911326c420cf8cd080"
    $a5="c9e4c132dbd8b4d69d151981b1e9add363a41618e42675744751ccd070b846d812aab3621ee5cace876dd74058b8b2362ed80f0ca5bbee66c1a5c9ff3ce10acd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}