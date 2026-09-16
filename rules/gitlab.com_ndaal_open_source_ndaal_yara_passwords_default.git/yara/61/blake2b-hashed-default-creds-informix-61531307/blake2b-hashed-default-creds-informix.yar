rule blake2b_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="60d311816dcf7f9218372d3d7742511380f53f1611c85666df0b309387618d65729213cc9155210a6de7ca221bcbdbe7a66676c8fd341378cf4494a336f85ddc"
    $a1="60d311816dcf7f9218372d3d7742511380f53f1611c85666df0b309387618d65729213cc9155210a6de7ca221bcbdbe7a66676c8fd341378cf4494a336f85ddc"
condition:
    ($a0 and $a1)
}