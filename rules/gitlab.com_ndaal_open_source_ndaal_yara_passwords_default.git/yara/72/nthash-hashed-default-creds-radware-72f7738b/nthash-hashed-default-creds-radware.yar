rule nthash_hashed_default_creds_radware
{
    meta:
        id = "14EWVbHBpRlIkmh9zIitzO"
        fingerprint = "c4a188d785b4e4843e341c779fcb7c0520897304ac3ae4d8bdb9640b2208c450"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="519512db08bed68c3ab7f7905fd06e6e"
    $a1="519512db08bed68c3ab7f7905fd06e6e"
    $a2="dd26f3e9d93404ea28f8ee393e3424d0"
    $a3="dd26f3e9d93404ea28f8ee393e3424d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}