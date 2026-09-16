rule sha384_hashed_default_creds_system_32
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58a775ba4112be3005ae4407ce757d88fda71d40497bb8026ecac54d4e3ffc7232ce8de3ab5acb30ae39760fee7c53ed"
    $a1="2e2fddef7ad9bd5cf3c941a536b0ccc4162a836d64d3e2d9aa3f155912de790677f40b950d95f1db55dfc623f0503762"
condition:
    ($a0 and $a1)
}