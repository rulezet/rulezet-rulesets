rule nthash_hashed_default_creds_trintech
{
    meta:
        id = "6mHSh5jIH1QW9JRXUCA21K"
        fingerprint = "6c4f486392a1ae886928400fce800e70d97611f9d0c39a0f2754ce5865381517"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74c17aa7b8d9a0dd7fc356ef356b7941"
    $a1="306e57aa04129e317c2cec787277a6f4"
condition:
    ($a0 and $a1)
}