rule sha512_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15249a9ac68a88215a642611eb1e97864358299439e9602d267265592617fc81c6b97916057d686fe5443baf38c1c37ddbba1f0274b431b1c0bd1cf81a466e1c"
    $a1="15249a9ac68a88215a642611eb1e97864358299439e9602d267265592617fc81c6b97916057d686fe5443baf38c1c37ddbba1f0274b431b1c0bd1cf81a466e1c"
condition:
    ($a0 and $a1)
}