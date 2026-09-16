rule sha1_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a1="c5fe0200d1c7a5139bd18fd22268c4ca8bf45e90"
    $a2="bd564db5d5cc358eb0e3523d3e03041739f230d5"
    $a3="a159b7ae81ba3552af61e9731b20870515944538"
    $a4="0f12541afcce175fb34bb05a79c95b76e765488b"
    $a5="2736fab291f04e69b62d490c3c09361f5b82461a"
    $a6="bd564db5d5cc358eb0e3523d3e03041739f230d5"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}