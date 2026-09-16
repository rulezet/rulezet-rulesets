rule sha384_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f02a6aa40a61e156fb4d174dff507f9426fd59e0059a6103d5973a3c51b372ae04f058215ba22a933e8d504efa1ba099"
    $a1="f02a6aa40a61e156fb4d174dff507f9426fd59e0059a6103d5973a3c51b372ae04f058215ba22a933e8d504efa1ba099"
condition:
    ($a0 and $a1)
}