rule sha224_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b9b91fc0a81a7cd89218aec69e635f94bedd7ab621c5d73dd0363de"
    $a1="4b9b91fc0a81a7cd89218aec69e635f94bedd7ab621c5d73dd0363de"
    $a2="5e177f81b6f935538b284d7e17884371b0d8e5fb5a7a79c2646588cb"
    $a3="834e8777f9e7b3392041178198cf7ecf1d3cd4d6d3194e5a030be176"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}