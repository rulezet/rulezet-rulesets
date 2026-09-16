rule sha3_384_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a1="2a353fed17cc1f251167abd4921a2f11817a257ba9a6736a9bee067d95ccead16fba1311aeb59528b350331b95d30ac4"
    $a2="ddfe867f7428f649622b80d66e82861531a6290f48ab2abaf22c5ec5bc00f989c99fc4ab86c5c8407aeefaa03c852ef8"
    $a3="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
    $a4="6eeb9a005a6a196390f7ab8bd7477922b7fd89c5b3768bdd27bf4da035206840900139baedabe0d888207bcdae10584c"
    $a5="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}