rule md5_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d0258c2440a8d19e716292b231e3190"
    $a1="1d0258c2440a8d19e716292b231e3190"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="1d0258c2440a8d19e716292b231e3190"
    $a4="3af00c6cad11f7ab5db4467b66ce503e"
    $a5="ae94be3cd532ce4a025884819eb08c98"
    $a6="3af00c6cad11f7ab5db4467b66ce503e"
    $a7="1d0258c2440a8d19e716292b231e3190"
    $a8="c962b86f3da856a9a67221a7df2038ee"
    $a9="c962b86f3da856a9a67221a7df2038ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}