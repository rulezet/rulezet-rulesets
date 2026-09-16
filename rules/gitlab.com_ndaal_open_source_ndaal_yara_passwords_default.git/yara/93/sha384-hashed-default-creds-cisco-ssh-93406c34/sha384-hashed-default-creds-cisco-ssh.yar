rule sha384_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a1="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a2="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a3="ebfcce5a94d625804ece72a70a1c36aeaba58bd2f034c9522e9c24a5dda030f66c106ff31255656c7bcb92c824c546da"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}