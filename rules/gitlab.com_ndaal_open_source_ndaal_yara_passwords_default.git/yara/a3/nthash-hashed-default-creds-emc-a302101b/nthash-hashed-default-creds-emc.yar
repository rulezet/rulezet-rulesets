rule nthash_hashed_default_creds_emc
{
    meta:
        id = "JSge0Sl8L1dmMj8d56s7f"
        fingerprint = "83f1dd2c173fdaca3065324b57cb57525fbd1aa4cda5fa538be12905172e0f68"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="20ef7eee1a0a2d1fec9aa7bf4a2b2163"
    $a3="ce5c7d0cadb3759fff94a538868f724b"
    $a4="0e2cdab5727c1e8079b9cc1b27d354cd"
    $a5="e1daa6cbc45a19807adf8d35e92e7ba5"
    $a6="6597d9fe8469e21d840e2cbff8d43c8b"
    $a7="86ac17999294d3eb7896c43cade27b15"
    $a8="4163ea3838183f7c4c209a535514bb6b"
    $a9="00b56d57e617705868a256e455a83759"
    $a10="46d2d4c24beafdf7063a8e32473345c9"
    $a11="c717d3d6938bfb0614cae483dd122baf"
    $a12="1053f6259c781a0c247da712cfa665ca"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="6597d9fe8469e21d840e2cbff8d43c8b"
    $a15="329153f560eb329c0e1deea55e88a1e9"
    $a16="065675866a2397120024e08d06f235a0"
    $a17="776d59d041cee7694a0e88d40da7bce3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}