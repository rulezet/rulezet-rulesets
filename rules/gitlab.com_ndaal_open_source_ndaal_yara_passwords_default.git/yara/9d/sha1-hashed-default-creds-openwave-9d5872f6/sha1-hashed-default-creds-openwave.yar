rule sha1_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c89849a005943e2be242cc820cdc3f87a7ad47c"
    $a1="8bcd0d793e5c24d3fbe6f2cd73f3dc8962696db9"
    $a2="81c64e156f5dd267d0df3d0934099771a1171b81"
    $a3="b4c56ee8d2854166dec66644f541b85247105b2c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}