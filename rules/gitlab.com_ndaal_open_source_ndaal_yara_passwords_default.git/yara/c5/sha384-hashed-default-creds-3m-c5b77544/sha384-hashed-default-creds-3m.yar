rule sha384_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
    $a1="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
condition:
    ($a0 and $a1)
}