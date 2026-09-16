rule nthash_hashed_default_creds_mitsubishi
{
    meta:
        id = "2ZX7veHhEyLhK3Ww2kZ0IS"
        fingerprint = "1433148dc405cd1dc24e714b7b8288b630e005401d408e7923d5f2db407a6bbb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d0c59435460e021d1824c9040e81e727"
    $a1="d0c59435460e021d1824c9040e81e727"
    $a2="5aca61349100788cad39e26a42646e81"
    $a3="5aca61349100788cad39e26a42646e81"
    $a4="7e88454bc2e541e1e8cedbd954fdcbdb"
    $a5="be36cdc66f71518575faf0da91de47fb"
    $a6="57d583aa46d571502aad4bb7aea09c70"
    $a7="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}