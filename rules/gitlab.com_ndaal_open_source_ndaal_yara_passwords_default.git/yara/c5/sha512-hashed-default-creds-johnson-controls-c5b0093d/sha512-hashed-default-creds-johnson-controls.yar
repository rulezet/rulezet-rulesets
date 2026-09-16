rule sha512_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c427caa8c8a2cb8b298c007210715886b6622767883d3fbbecd50a4009c06dfc72aca70e73aa1f0d90a9dabc5d5349d450c6c181c43fdec5d6f250cd5ee58e9"
    $a1="338f820430095e0a1486ad94a8b0d43113a942a24646097a139da23fb58ceb1894c7b7a8e1f5f7e980960cf1c5a0bcb7e80ad901c55c8e829bff04e7626f6569"
condition:
    ($a0 and $a1)
}