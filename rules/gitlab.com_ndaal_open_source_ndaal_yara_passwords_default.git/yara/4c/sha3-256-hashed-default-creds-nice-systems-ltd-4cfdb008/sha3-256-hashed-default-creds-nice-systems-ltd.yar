rule sha3_256_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cf3b2ffb2d0216861534a8064e6ce3662ccd643e6a76ec12cb84ba1e8ca9bd43"
    $a1="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a2="cf3b2ffb2d0216861534a8064e6ce3662ccd643e6a76ec12cb84ba1e8ca9bd43"
    $a3="5c3a2a84d6c383d245654d508863a73004e9062ca8481a9f54fa3da9f7e72697"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}