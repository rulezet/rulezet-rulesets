rule nthash_hashed_default_creds_crt
{
    meta:
        id = "3GuV8Ro00q5XQHhWHJ9izh"
        fingerprint = "a8ce07733e105d473d1b2fb85f06074de5405fdcbb888807bd1f7ba6e203d760"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a38f10fd207668ca5ddb097fc95b9ce"
    $a1="b37a1ed2e1f2c0cd5077011c71d0c032"
condition:
    ($a0 and $a1)
}