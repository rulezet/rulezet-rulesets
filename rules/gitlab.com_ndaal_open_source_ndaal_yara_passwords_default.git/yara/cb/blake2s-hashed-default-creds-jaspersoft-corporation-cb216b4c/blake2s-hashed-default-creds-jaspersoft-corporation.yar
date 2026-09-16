rule blake2s_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a1="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a2="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a3="b5f807b5814ccf4f8d73f88fc13f180a7bd6d9966b36cdab9cb95b8cc2f91c77"
    $a4="6223e24f2373486564e57a7c9124f5b5fba0e00bf8e54cd5830ffe10ec7b3fd7"
    $a5="6223e24f2373486564e57a7c9124f5b5fba0e00bf8e54cd5830ffe10ec7b3fd7"
    $a6="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
    $a7="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}