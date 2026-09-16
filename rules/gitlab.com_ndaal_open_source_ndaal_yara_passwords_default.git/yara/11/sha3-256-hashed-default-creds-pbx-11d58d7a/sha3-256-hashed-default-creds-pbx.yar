rule sha3_256_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7257ee9b283f8079536ac3d0eb2e966b127875124b5aa45c6fff5e54759e7a19"
    $a1="6bb4c8e14fe4dc77a7a27a5d75c181cffa632c0c2907086c0f67fb9a55016b96"
condition:
    ($a0 and $a1)
}