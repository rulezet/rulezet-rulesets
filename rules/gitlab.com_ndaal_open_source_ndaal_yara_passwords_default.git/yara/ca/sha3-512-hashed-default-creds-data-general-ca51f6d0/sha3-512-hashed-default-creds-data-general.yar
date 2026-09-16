rule sha3_512_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a1="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a2="eabfe45c57ddcb5cbb58d2a91eaa40a645d1e50026ffef32a5743bfafd8d73165ffd8f21fbf1d1dd147b39b10feb19bfc3ec7b4d54d1f54f8f8d6ad1475ec8bf"
    $a3="eabfe45c57ddcb5cbb58d2a91eaa40a645d1e50026ffef32a5743bfafd8d73165ffd8f21fbf1d1dd147b39b10feb19bfc3ec7b4d54d1f54f8f8d6ad1475ec8bf"
    $a4="eb65ed18f38a818be59cfc0c06cc812c1b46ead14d3059b3d0ea8fe388119ae93c30df5ceb94dfd0a2dba10e062066edf65951d4ab734c7f953f95e669d2a0f5"
    $a5="eabfe45c57ddcb5cbb58d2a91eaa40a645d1e50026ffef32a5743bfafd8d73165ffd8f21fbf1d1dd147b39b10feb19bfc3ec7b4d54d1f54f8f8d6ad1475ec8bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}