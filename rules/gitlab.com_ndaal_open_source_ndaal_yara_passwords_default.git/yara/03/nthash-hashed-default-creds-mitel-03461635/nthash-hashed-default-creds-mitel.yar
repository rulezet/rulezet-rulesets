rule nthash_hashed_default_creds_mitel
{
    meta:
        id = "4SN57x8oEhW9KVjrDlyAzx"
        fingerprint = "1ae9caf12a7094d53978bb9fea50d91ac5e314a7edf14bd4122dc97f9f529b87"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
    $a2="fb2c93d6b3efd4457eda5d20946874e4"
    $a3="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a4="9ac57542fcc0f81340609112c9027171"
    $a5="f441f41aa59214cccc3d4ba5ed1550cc"
    $a6="926a8cfd663015507720a7c1d476aa55"
    $a7="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a8="1ebdada6bd574848235b783ff6578fe6"
    $a9="f441f41aa59214cccc3d4ba5ed1550cc"
    $a10="76178e956fc1907df6d1eb623675f1d5"
    $a11="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}