rule nthash_hashed_default_creds_sprint
{
    meta:
        id = "4DuaxhKB3x94375waJFd6J"
        fingerprint = "983eaac7aea6dbe845709a98cb62f70feb6f7cb9a312995578fcb4efe3a13a25"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sprint."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f441f41aa59214cccc3d4ba5ed1550cc"
    $a1="dfc022a93803dc9c5566648ec13cb085"
condition:
    ($a0 and $a1)
}