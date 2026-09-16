rule md5_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a27eb684802bfd8963b4520f35c082b"
    $a1="172192ec5eb1a7893cabbd2418691eb6"
    $a2="b9a2687707534d60726a28ec47d13939"
    $a3="b9a2687707534d60726a28ec47d13939"
    $a4="6c34629835d389f3cc4b449f2e551f5c"
    $a5="6c34629835d389f3cc4b449f2e551f5c"
    $a6="0cf972b58ef9c84f68d98f1e42df0edc"
    $a7="0cf972b58ef9c84f68d98f1e42df0edc"
    $a8="3d60ed60dc05663587f78e3f7078a3e0"
    $a9="3d60ed60dc05663587f78e3f7078a3e0"
    $a10="b3ed03788b9229834f1d7abda17ce672"
    $a11="3d60ed60dc05663587f78e3f7078a3e0"
    $a12="d31297d2c5ef01ac1b5f74ad8d3c8d9a"
    $a13="3d60ed60dc05663587f78e3f7078a3e0"
    $a14="2f1c5e5191255007f2833450c4acdb27"
    $a15="3d60ed60dc05663587f78e3f7078a3e0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}