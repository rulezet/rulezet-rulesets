rule nthash_hashed_default_creds_advantech
{
    meta:
        id = "6OMk2ryJQw82RxvKLOFALy"
        fingerprint = "e50a3a482b7fe8107b2a13617246452b50049a64bf23596f52dd754f9adc5c6d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="59380d48b907d5c718e714159a57edb5"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="9bdc61db5a3fced6d82d49279f1f0430"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="9bdc61db5a3fced6d82d49279f1f0430"
    $a7="0d17ae3710227fa4cd6b0ee3269c7f85"
    $a8="9bdc61db5a3fced6d82d49279f1f0430"
    $a9="a25b2710ba9de114396adc7dfb0a7235"
    $a10="9bdc61db5a3fced6d82d49279f1f0430"
    $a11="0280777f37d4f4e7c478d21cec701463"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}