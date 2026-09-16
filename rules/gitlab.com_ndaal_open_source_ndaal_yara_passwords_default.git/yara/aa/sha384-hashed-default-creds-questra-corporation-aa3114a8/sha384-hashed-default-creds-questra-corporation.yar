rule sha384_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a1="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a2="f1d452df943dd389985400608635bbd32dd45edd1b11523333cb33be9f27f34e885c733ad8229a541fbece8715a8f233"
    $a3="f1d452df943dd389985400608635bbd32dd45edd1b11523333cb33be9f27f34e885c733ad8229a541fbece8715a8f233"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}