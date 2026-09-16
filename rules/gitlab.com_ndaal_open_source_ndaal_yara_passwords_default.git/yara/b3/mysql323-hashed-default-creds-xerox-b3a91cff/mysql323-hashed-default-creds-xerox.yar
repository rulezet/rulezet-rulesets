rule mysql323_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76274ae801fb95ce"
    $a1="43e9a4ab75570f5b"
    $a2="465ff47d58c823ca"
    $a3="43e9a4ab75570f5b"
    $a4="43e9a4ab75570f5b"
    $a5="43e9a4ab75570f5b"
    $a6="0a4c13b504926a4d"
    $a7="43e9a4ab75570f5b"
    $a8="76274ae801fb95ce"
    $a9="623df14f1fd6c1e4"
    $a10="45271aba0b765d95"
    $a11="43e9a4ab75570f5b"
    $a12="6eddce4c69159e8f"
    $a13="58f7ee435f925abe"
    $a14="7a28321826fa4591"
    $a15="70cbdcb81fe7cfd1"
    $a16="58444a6f34d81fc3"
    $a17="027d49ca469919b3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}