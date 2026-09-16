rule sha3_224_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8fc6bdca98e7dd15834e3f50b203bc92be7f79c48d5eab77a637885"
    $a1="f8fc6bdca98e7dd15834e3f50b203bc92be7f79c48d5eab77a637885"
condition:
    ($a0 and $a1)
}