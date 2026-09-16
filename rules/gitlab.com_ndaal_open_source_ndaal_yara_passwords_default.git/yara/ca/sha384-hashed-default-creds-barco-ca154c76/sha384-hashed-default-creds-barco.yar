rule sha384_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84fb09de18d99afbbd5310644c294c55ad1e111e4fbe0342b163a71b68cca35910370cd1243ce57112fc9ff4b0d6b873"
    $a1="cc8c8df4102a6d0dc7d7faa34d839282d66fc247564b4ca9f89a3bee928133cb5ab04d6ec710bf1caca34655af6a9abd"
condition:
    ($a0 and $a1)
}