rule nthash_hashed_default_creds_zyxel_ssh
{
    meta:
        id = "8b5UoLb8qpwGZFw7g3FPu"
        fingerprint = "931d47aaa920a49fa1523b91d2f78750efb820577a8ca3acf62390b2f0c783be"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3893dc5543bf510bcddd9e6a00700cf9"
    $a1="4b1c17e86d6a31b04979b4d554a73f71"
condition:
    ($a0 and $a1)
}