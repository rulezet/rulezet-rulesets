rule sha224_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9dbfdebc83bb85be8204293e1ac7ab6aab8e6f07b2521f5ca608196"
    $a1="a9dbfdebc83bb85be8204293e1ac7ab6aab8e6f07b2521f5ca608196"
    $a2="f627abca2eca9ad27bf89b9afff4cdd60b4dd361c314de203632b633"
    $a3="5cd534249a0867d4243f7192f71dd46d37310097d3d70b1582dd6751"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}