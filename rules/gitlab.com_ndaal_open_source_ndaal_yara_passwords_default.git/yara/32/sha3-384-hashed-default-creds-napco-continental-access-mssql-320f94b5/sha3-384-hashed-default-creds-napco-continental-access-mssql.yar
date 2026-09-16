rule sha3_384_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a1="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a2="9929168af61528e55d28a8052ea346e64983547f3533f8b4a94c679aff656397e20be03dc0c164cf939ef4c038a9f99c"
    $a3="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a4="90d8b2614e03cbd3e27035e740262081af34faf99b266f8ca0735c9f7173dd62d94fd88ad58b1a540e56ef1e57d95a11"
    $a5="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a6="d5be957d44de801c1a98af610e07064b00ee664dbafc6524260497ee4291aa29738f8e7377280dbf87d5ec175b18e17b"
    $a7="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a8="9929168af61528e55d28a8052ea346e64983547f3533f8b4a94c679aff656397e20be03dc0c164cf939ef4c038a9f99c"
    $a9="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a10="90d8b2614e03cbd3e27035e740262081af34faf99b266f8ca0735c9f7173dd62d94fd88ad58b1a540e56ef1e57d95a11"
    $a11="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}