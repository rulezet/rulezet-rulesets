rule nthash_hashed_default_creds_phpreactor
{
    meta:
        id = "4WUS7SX8XJPv3A5B0vpd3h"
        fingerprint = "c1c827b5fe649a91232c8d833d63b28af72a2cc85bc27489f4d7da2a78bc101c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08d0879affb14215367aea4a5c3e266c"
    $a1="4d44c04cc58fb4fece364e3095b287dc"
condition:
    ($a0 and $a1)
}