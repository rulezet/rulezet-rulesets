rule sha512_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21fc367a8c45f77d415c9fb4612f333a69b21a8e0d4da3a73a9b20da90dd5b87ece951db51123c642c9c217abd14f0fc4519ab35c495fb901a6b26a6b7016320"
    $a1="9ad0d01d1766bb60025ba3403e851d1493a1ce2f14bdcf14d198f4a49e083f4547a6e5f9908444aad02d8d2383fbc74af021c7ee797ea13254c6603de76291b8"
condition:
    ($a0 and $a1)
}