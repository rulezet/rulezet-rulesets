rule sha3_512_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a221ad4b83384a87429f1731409b6572699ec55ea9dc06900548bc22c149126f7c73c3c92fbc4b75386924242aaad351761f5b96d33188125908bde290e6a83a"
    $a1="a221ad4b83384a87429f1731409b6572699ec55ea9dc06900548bc22c149126f7c73c3c92fbc4b75386924242aaad351761f5b96d33188125908bde290e6a83a"
    $a2="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
    $a3="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}