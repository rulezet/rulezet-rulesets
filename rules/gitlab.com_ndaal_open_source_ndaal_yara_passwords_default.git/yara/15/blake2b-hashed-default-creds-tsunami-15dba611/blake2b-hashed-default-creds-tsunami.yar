rule blake2b_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd771f69114d62cb014c91fbc6fabdcd1afba71292a1fc5b075100c88370eb53b056f1af869215d3d6a47ce61c75a298001fb9506849ee148a33285722801fdd"
    $a1="dd771f69114d62cb014c91fbc6fabdcd1afba71292a1fc5b075100c88370eb53b056f1af869215d3d6a47ce61c75a298001fb9506849ee148a33285722801fdd"
condition:
    ($a0 and $a1)
}