rule blake2s_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe66151dc72f3161b43d055f19b17cff31c8b1da3c4c5acb9935cea25186f1c7"
    $a1="fe66151dc72f3161b43d055f19b17cff31c8b1da3c4c5acb9935cea25186f1c7"
    $a2="135184fa03c0249f93e3c035457f986f887f294798f57efb63ff46391264cfa6"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}