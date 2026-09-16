rule sha3_256_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="158eb0750556203dd8bd4b33ed14eb1edc1c288179976184907382ceaf20f876"
    $a1="40949c5e0e3b5b2daf7d42826f8001a559b06b19d6eecbc20c7b854d6339425a"
    $a2="25e2ebb10fe636c7409d4eefd998175dbbe301b55440e545eec48b5b020b97d4"
    $a3="6a95043d52b79febc32cfd56092e0fbc36cb691bc88491da6f9f509821451e85"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}