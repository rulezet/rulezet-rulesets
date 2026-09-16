rule sha512_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e055d249efc8f9381537a966433b628b8f54cd85e129386d0c5186a8d54a0c079381800d236ae2f26cbb125d7ecdc859761a9a7cb142fd608f8212764574e04"
    $a1="1e055d249efc8f9381537a966433b628b8f54cd85e129386d0c5186a8d54a0c079381800d236ae2f26cbb125d7ecdc859761a9a7cb142fd608f8212764574e04"
condition:
    ($a0 and $a1)
}