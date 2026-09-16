rule sha384_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a1="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a2="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a3="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
    $a4="1702a7ec5fdd7fe0bcfba42540dcec86100dfd22d8940b6ac8c623769f3faba5621ddb61cab9bd66e00199b2edb2ba34"
    $a5="3ce313ec5ea0e8e20c6d3e0a70418198cd3cc1a54bb1e51f1a3135dc03d014e20f3387875bba5f5d37e54100b9535762"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}