rule sha512_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9f5306438d93f5ab53422ae35822449cad534355db57f47139841bef1d68c24190a68b0efb297bd4c36e8a1bb2ae302b24a35cb3d29657236a8b822e1c0c265"
    $a1="ce430ec96b8cc77d15429b6e49318d6c8c3084a7214227fa18a8a86f27a09ce2af081859c63892c9b72a034faa519387e1d9b4725d865e9a866120a2e5ff038e"
condition:
    ($a0 and $a1)
}