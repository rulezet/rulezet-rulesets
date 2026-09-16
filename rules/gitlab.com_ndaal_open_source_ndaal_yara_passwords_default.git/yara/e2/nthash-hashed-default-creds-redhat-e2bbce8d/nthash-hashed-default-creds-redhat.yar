rule nthash_hashed_default_creds_redhat
{
    meta:
        id = "6XQGZnrxvbQsMkxrppwVcd"
        fingerprint = "18bb7a9d87ea68c82bae49e985fe522ed7d143ba746bd28a1d3b13721be1d2ac"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ff233ecf5526941e22a0766d926d79a"
    $a1="5ff233ecf5526941e22a0766d926d79a"
    $a2="64f92a7257f6e6e48d2be10daa793463"
    $a3="5ff233ecf5526941e22a0766d926d79a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}