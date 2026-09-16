rule nthash_hashed_default_creds_schneider
{
    meta:
        id = "62hIKMWc4dTSN7oEbweX2j"
        fingerprint = "a2ee489329a8579b3c72c2286b31cf96a863c3d08c2cd92a706cf3a09b4ac855"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96388f27c95e6f7b15180198c1226aa4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="4cc0bb6640549818648ede0d9747696f"
    $a3="67f6c767ad13d1986980a9bc2ba55b6d"
    $a4="d5cf1723c208af23eb6222aec2bf415d"
    $a5="0a6f495948c7df2bdfbab10949b590f7"
    $a6="f71c06917bd3033942e82649ac7f98b3"
    $a7="6d5fd8fe631f0f71625e078548e5d7c5"
    $a8="e768fd2ff41b87534f7aef3e4516adf3"
    $a9="9fc6f8f7b33dab7f3cba2fac269cc3a6"
    $a10="467799ec546cddb461f187080eebb40b"
    $a11="467799ec546cddb461f187080eebb40b"
    $a12="4c845126bfa610c7839dbedc76a8bc1b"
    $a13="467799ec546cddb461f187080eebb40b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}