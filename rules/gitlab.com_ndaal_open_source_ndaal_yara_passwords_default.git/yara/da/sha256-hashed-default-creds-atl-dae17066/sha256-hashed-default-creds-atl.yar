rule sha256_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8638b979b2f4f793ddb6dbd197e0ee25a7a6ea32b0ae22f5e3c5d119d839e75"
    $a1="d677190e0a9990e7d5fa9e4c1bbde44271fb8959c4acb6d43e02ed991128b4bf"
    $a2="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a3="06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}