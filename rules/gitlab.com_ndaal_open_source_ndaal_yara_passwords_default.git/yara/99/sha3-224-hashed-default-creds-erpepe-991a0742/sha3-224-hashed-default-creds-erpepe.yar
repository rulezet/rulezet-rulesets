rule sha3_224_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="41299c884b7a9e7384e346ef3cf731cc35827f91d6de33667f776cc2"
    $a1="142da49f6474a54e8e3c908a53b095a06e3c92bf03a6a10ac0ca57a1"
condition:
    ($a0 and $a1)
}