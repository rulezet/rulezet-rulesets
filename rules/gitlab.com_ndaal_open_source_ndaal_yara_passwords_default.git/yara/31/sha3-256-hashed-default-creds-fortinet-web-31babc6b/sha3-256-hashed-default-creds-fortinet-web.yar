rule sha3_256_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="690e36fa8c6440b20da312da2f328bd061f155526fff967b1062f6e30c976ef2"
    $a2="1389aaa1b3d602373f1464b377f93d024e74a12379d10627963b05c302aa7ad3"
    $a3="690e36fa8c6440b20da312da2f328bd061f155526fff967b1062f6e30c976ef2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}