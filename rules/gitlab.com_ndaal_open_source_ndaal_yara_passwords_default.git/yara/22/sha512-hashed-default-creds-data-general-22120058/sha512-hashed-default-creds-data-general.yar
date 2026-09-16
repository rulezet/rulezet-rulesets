rule sha512_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a1="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a2="36eb6902784e66e624b831d25208b67ff26198fcc87d7484f51ccadcc50e3c27e9bd75aa2bfb983fc9978098c70dbb45e2db9fdb20005ad45f3a6c73e4c33298"
    $a3="36eb6902784e66e624b831d25208b67ff26198fcc87d7484f51ccadcc50e3c27e9bd75aa2bfb983fc9978098c70dbb45e2db9fdb20005ad45f3a6c73e4c33298"
    $a4="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
    $a5="36eb6902784e66e624b831d25208b67ff26198fcc87d7484f51ccadcc50e3c27e9bd75aa2bfb983fc9978098c70dbb45e2db9fdb20005ad45f3a6c73e4c33298"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}