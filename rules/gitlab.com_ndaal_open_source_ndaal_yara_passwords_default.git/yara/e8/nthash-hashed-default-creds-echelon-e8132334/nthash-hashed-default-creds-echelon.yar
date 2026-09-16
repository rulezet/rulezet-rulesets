rule nthash_hashed_default_creds_echelon
{
    meta:
        id = "6cKalYLqNwFQ9SrtNcYjue"
        fingerprint = "3d0d2d5033a56f167450339fb3e81e7b975caf8ed7a57182205db0257d32aa34"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff765d296da26840854d84126e8ddfb2"
    $a1="ff765d296da26840854d84126e8ddfb2"
    $a2="2c51b2ab1045cc2da80d9a352281521a"
    $a3="224c410159eebdf789c9d9f3104242eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}