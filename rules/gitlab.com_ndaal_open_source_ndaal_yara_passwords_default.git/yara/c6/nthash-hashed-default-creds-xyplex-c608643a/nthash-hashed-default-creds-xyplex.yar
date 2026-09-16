rule nthash_hashed_default_creds_xyplex
{
    meta:
        id = "5qVpe7oT3PYqWEiH8rUR94"
        fingerprint = "1aa09ec8f79d6f5563f85418697633dca1730aaf905e8c5a9471bd3fbca476dc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xyplex."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f441f41aa59214cccc3d4ba5ed1550cc"
    $a1="305525d6b47f486972c80697b56acebe"
condition:
    ($a0 and $a1)
}