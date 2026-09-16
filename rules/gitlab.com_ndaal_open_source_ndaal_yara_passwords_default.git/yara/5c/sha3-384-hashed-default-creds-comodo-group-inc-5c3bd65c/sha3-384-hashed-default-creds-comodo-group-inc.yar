rule sha3_384_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f10aba19d403b82c2f488bd2b96843e500cfbb92440076c9f3b8ba1a233100fb0c208661a9af98fb705a71cae056e862"
    $a1="f10aba19d403b82c2f488bd2b96843e500cfbb92440076c9f3b8ba1a233100fb0c208661a9af98fb705a71cae056e862"
condition:
    ($a0 and $a1)
}