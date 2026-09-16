rule sha384_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="172b0067e069e237ba0f102f1ef1bcc2a365c4d325b0255debba924d3effe2bf090a4ec7ccf33aae860a87a519ed6677"
    $a1="172b0067e069e237ba0f102f1ef1bcc2a365c4d325b0255debba924d3effe2bf090a4ec7ccf33aae860a87a519ed6677"
condition:
    ($a0 and $a1)
}