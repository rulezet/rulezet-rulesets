rule sha1_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f3237e14a7beb1e3f598866a2f2959c7e11729f"
    $a1="d5668af487c01ab83515c90eb3952a7f9677ebcf"
    $a2="553b35f8e572aca9a6538d5d6e997aeb1411cb1a"
    $a3="821751d8ab4c6d75d927e7f092d55be896f7f67a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}