rule sha224_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd"
    $a1="bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd"
condition:
    ($a0 and $a1)
}