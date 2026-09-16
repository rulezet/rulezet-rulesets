rule nthash_hashed_default_creds_becu
{
    meta:
        id = "5UE1Ra0qlyBY4zXAjgYF7M"
        fingerprint = "d8ec997c6083eba2b58e02fcbd69840078b69ac64e66e835cfe0355a9cf7ef54"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="039d59247b08efb9689cf182c13dcb7a"
    $a1="d07fa4a6c97383641ae3880fa7de9656"
condition:
    ($a0 and $a1)
}