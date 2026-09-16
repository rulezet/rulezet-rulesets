rule sha3_256_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8d5a6d907c60a4b195d31867ac037819446197d7e3d8a0ea5f9f8cb14d66f8c"
    $a1="7d2f5fc2f92429cdb7f9e504896b6e776567cd5bc8906460b724562219b93713"
    $a2="a2e706707e353d09147b7de375589d26f2153ee706b38a48433e7e90f0b44a4c"
    $a3="2440602c0d1c3adbb2ee9485506eed4b1ec0f20bcca3ea2ddbb10a351fe85911"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}