rule sha384_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82488aef6a1e7e27f2fed25da07a4e8b2500bdfd125b15e927d22de129fdc16858b1c9f8133112c3349114dcd59b0b5b"
    $a1="edd90d4380e18e8ac54cf72e8802d35fcb929b5c26ff819498eb08b0b3de7aa76331eabf64fae2206e2388cf013199cc"
    $a2="82488aef6a1e7e27f2fed25da07a4e8b2500bdfd125b15e927d22de129fdc16858b1c9f8133112c3349114dcd59b0b5b"
    $a3="2b3574a9fad343bb0856da62a7aa719c117510bca31e766ba77061930cbe3cf38fa84c54fc3140d00830140ac4e04b07"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}