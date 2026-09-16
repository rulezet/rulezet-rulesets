rule nthash_hashed_default_creds_apc
{
    meta:
        id = "6nGEarwGVsm5Xc9dLVK1Hg"
        fingerprint = "1dd16592fd71c24bd43cea968e71de414cc6981762f1913316266a4418df8eb0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b96670ba87df193012a9b0ddbf14c634"
    $a1="8ed8b6f2aaeda80e8c9c4055bacf910b"
    $a2="b96670ba87df193012a9b0ddbf14c634"
    $a3="b96670ba87df193012a9b0ddbf14c634"
    $a4="520bb2211c403f0feefe4e7e6bcb9260"
    $a5="9d2e8cd56c5c7f34993c58bae7537778"
    $a6="b96670ba87df193012a9b0ddbf14c634"
    $a7="dddbcb37e837fea2d4c321ca8105ec48"
    $a8="b96670ba87df193012a9b0ddbf14c634"
    $a9="5d93591697ff29acfa4eb6a086205cf1"
    $a10="5d93591697ff29acfa4eb6a086205cf1"
    $a11="5d93591697ff29acfa4eb6a086205cf1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}