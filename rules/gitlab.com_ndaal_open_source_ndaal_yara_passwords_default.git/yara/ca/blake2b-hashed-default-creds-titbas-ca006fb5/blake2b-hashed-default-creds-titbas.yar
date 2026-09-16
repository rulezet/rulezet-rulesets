rule blake2b_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="df3071019dace3235c3765614d8136588bb704ef6229289e48769df35cb534c6dee175881d44bc06f915e685585a16587d3ba9b964123ffe22a8a00badcb2b41"
    $a1="87cbfc2d6506ef091cbe587e7b845076edec5b1e122322dbae920de7f76827caa8861ea9183ff5bc08c9693ca05c027431e8e345fbe0326f069d3e4e91ef0813"
condition:
    ($a0 and $a1)
}