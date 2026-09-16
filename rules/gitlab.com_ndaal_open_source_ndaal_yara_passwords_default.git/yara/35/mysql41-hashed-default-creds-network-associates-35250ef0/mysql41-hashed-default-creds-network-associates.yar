rule mysql41_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2AE762C3A0B77AB3F6EED1899AAF4B9C8943049F"
    $a1="*C45417D73D58916A2F12801E186183E9152E4278"
    $a2="*3008C020B29414C227DE4977251C6938B3063B84"
    $a3="*2B50AFE0489C9D567857C70CF8EF155D9D8066FB"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}