rule sha256_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="2f04672311c5a91443c7a2d68148f46acdaeaeb3e488c587b9172a23f67647f0"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a7="44cb005ee2e65d9cc817b0a083579369fb6c24a4be728cb43fd9d4c3ca7f4c2e"
    $a8="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a9="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a10="7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
    $a11="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}