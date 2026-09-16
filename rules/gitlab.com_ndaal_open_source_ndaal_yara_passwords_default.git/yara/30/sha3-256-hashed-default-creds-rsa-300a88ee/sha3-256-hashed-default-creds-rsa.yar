rule sha3_256_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fc68b83499793838b29c32aa0661f4ef2cc03f49446de9499bb5d17994c850a"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="6c1399bd25719b90b17bb05a4170ac1c9ecf6c95511402873ddadc77b3f05bec"
    $a3="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a4="40e78fc0cde06cd0126ea72c7080364433068fcff61a73d1236d8e802fc5fae6"
    $a5="8e5d79468855b0aa30152460f869669ebece49a748839c70f19d17bb2a2239e2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}