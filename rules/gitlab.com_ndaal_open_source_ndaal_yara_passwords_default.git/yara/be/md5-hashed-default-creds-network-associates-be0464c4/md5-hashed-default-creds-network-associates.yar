rule md5_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85d45488b210c628e0816f146eb809b4"
    $a1="9d82d05cc097f966e26b0cb0bd6bbe2b"
    $a2="7e700a165df76746530903ba4f2922d9"
    $a3="f486c0003adcc21bf1ed25067e5a89e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}