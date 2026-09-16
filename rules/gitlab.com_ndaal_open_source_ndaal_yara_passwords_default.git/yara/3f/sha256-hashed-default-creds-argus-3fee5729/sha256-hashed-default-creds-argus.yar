rule sha256_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48c5a1d217fe85082464d2ca1e90a16d15464fabe20f8610d79b63aa58797b9b"
    $a1="cc4fed175f09f5095e026bb8b492e1a4baa11500ebab0866aecdbee6c44d2ede"
    $a2="444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97"
    $a3="444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}