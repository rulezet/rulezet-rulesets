rule sha1_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb39bb55c95ecae0d777841ec4686d53c2f3d542"
    $a1="ff8f5c593a01f9fcd3ed48b09a4b013e8d8f3be7"
    $a2="f865b53623b121fd34ee5426c792e5c33af8c227"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="6d585f738148fa78dcd8eed0c72d556082647838"
    $a5="aece0db4254c765e46f7595b6db90c517122556d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}