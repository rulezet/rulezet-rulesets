rule sha512_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc35aea6b82b5bb7152fe5c78ad7c87e38ae06f9b5749cd7e22dfd5498aa5f84b5b1bfa1b387eea6c4f41de2b14bcfca795a07fe420268945fb3366dbe81c662"
    $a1="b1a522ae5d2b9b0738a182a7e16d8553ea5013b92a350cdc7fe7a870fe5946fee0bf267631a061fd386b896b54d5d3f76b09ecdcf0323ffc2fcd0a9a5b7bb36f"
    $a2="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="acf4fd04a648ae5754053813e74c37ed875e024caabe9905ccff0441cd18efb969a58089ab4a60a51545f03ebfb94220105a47185a6aeaf108851cfc513cb7f6"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="768232fcb74ab2fddea8bec15e6c845f11b6f79094303ba75481787291237982ca28e8e14a84045da8f3b2e5e9659ea285b7a1c7987172fdd6ead28cf40998d6"
    $a7="768232fcb74ab2fddea8bec15e6c845f11b6f79094303ba75481787291237982ca28e8e14a84045da8f3b2e5e9659ea285b7a1c7987172fdd6ead28cf40998d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}