rule sha3_512_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f9369583a0dbb2f14041e9149a05ba44ab290f0e1e7e515070f0a92cf6d48d0b886b5593afb0473603b9b6edd0d1566666f317fe317fc5f5d60aa50b3a8b459e"
    $a1="1b553e6e2f919758eaceb4c940055d95507e3a6f2bc82252dac4ba0e72bfd3cb1faff77f8d2d727c309ecc92f3571f92dc5cd1c77ab1d62c91e3187da543026b"
    $a2="00ec7004fc7306dcdb8cda65db82cd35a68b6c9146a2afc84e112c97c71f8e016fbd113fed86326fb3787dcb13274b25e3f909c58fcfdcd13c18e82905f1f464"
    $a3="00ec7004fc7306dcdb8cda65db82cd35a68b6c9146a2afc84e112c97c71f8e016fbd113fed86326fb3787dcb13274b25e3f909c58fcfdcd13c18e82905f1f464"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}