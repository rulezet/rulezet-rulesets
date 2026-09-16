rule sha224_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90155d3dfe0beb7689fa60dced7f07844014b60d9c86f36c180fe5a3"
    $a1="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a2="904e1dfdd115698ca60d626134dd92d5f3362df3cd4bcf8fde0501de"
    $a3="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}