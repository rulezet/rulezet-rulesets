rule sha224_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff265e0ac8881bdb8a64ab653840c680d81670519b88585f958a896d"
    $a1="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a2="638d1fe493896e76363a57926604a0ccf9e825aafa96c659f8657614"
    $a3="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}