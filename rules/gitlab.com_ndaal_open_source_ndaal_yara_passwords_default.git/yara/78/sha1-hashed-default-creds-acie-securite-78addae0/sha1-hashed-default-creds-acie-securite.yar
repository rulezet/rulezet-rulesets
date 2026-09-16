rule sha1_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="c548ed53c99449bb838aa54fe0dde85db00b22ac"
    $a2="00ff262976e32557950c39bd1061176fb1cfa02e"
    $a3="c548ed53c99449bb838aa54fe0dde85db00b22ac"
    $a4="aa7ba874b7e98cfe4cb65e9282fe72e1d31d3669"
    $a5="c548ed53c99449bb838aa54fe0dde85db00b22ac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}