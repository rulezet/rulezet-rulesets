rule md5_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a27eb684802bfd8963b4520f35c082b"
    $a1="a339abb79d3007eac86137a460f32c9e"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a4="42f749ade7f9e195bf475f37a44cafcb"
    $a5="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a6="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a7="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a8="0c0134c0cbebf48be8c95920f5ea74fc"
    $a9="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}