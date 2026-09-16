rule sha3_512_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="27d26f0dbd2f196cbfed387e9d20a0212bbe393526e2a1b7a087daf685fa08c3f3dee888d40785deb7fa8f693b79ce051c85bf3e6913c8d10278f23f65099d85"
    $a1="5eb357f631c3d51249eb289d202ab341050cb40eeb35e1ffb3224fdfb3e478b36750312c592fc20f1a5c8de1c2b7b290940e518dd92c982238f0c1e9d719aa17"
condition:
    ($a0 and $a1)
}