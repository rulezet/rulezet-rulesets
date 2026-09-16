rule nthash_hashed_default_creds_apc_network_management_card_web
{
    meta:
        id = "5r9waC7Cq1YBzTMAQpc0Xf"
        fingerprint = "c59764836af40358a43ff6a7b5d514a9b036a1b1943fc35afce4a789e9bc3f55"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b96670ba87df193012a9b0ddbf14c634"
    $a1="b96670ba87df193012a9b0ddbf14c634"
    $a2="b96670ba87df193012a9b0ddbf14c634"
    $a3="5d93591697ff29acfa4eb6a086205cf1"
    $a4="b96670ba87df193012a9b0ddbf14c634"
    $a5="dddbcb37e837fea2d4c321ca8105ec48"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}