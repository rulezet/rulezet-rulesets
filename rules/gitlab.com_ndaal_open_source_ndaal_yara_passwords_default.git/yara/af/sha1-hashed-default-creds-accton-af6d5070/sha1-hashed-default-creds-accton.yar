rule sha1_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a1="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a2="9796809f7dae482d3123c16585f2b60f97407796"
    $a3="9796809f7dae482d3123c16585f2b60f97407796"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}