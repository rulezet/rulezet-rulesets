rule sha3_256_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a1="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a2="25b32184d8410e57df05a91c1fce6e458ac880a144321bf9e14944c1f07bfa34"
    $a3="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a4="fd055150cfa1f6e3da04cc4d9d89f4ce306addde4a1e0ee1ca032d302e590221"
    $a5="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a6="53864472ab9f796c73a8266cdbeef31974a1ddfd192f80929fb5d45f60f89a7f"
    $a7="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a8="25b32184d8410e57df05a91c1fce6e458ac880a144321bf9e14944c1f07bfa34"
    $a9="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a10="fd055150cfa1f6e3da04cc4d9d89f4ce306addde4a1e0ee1ca032d302e590221"
    $a11="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}