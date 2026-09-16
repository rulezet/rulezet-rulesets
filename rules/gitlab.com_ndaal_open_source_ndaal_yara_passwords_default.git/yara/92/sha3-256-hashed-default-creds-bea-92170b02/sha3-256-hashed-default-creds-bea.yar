rule sha3_256_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="c7c348cf88383c25ae5c394ba71c2e92e7698df98c7f523cf8aab6bf9965ff36"
    $a2="10414145323772df86d67f55a07a80e989ba7d893f8fa9a79031b2d7000ecdb9"
    $a3="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a4="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a5="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}