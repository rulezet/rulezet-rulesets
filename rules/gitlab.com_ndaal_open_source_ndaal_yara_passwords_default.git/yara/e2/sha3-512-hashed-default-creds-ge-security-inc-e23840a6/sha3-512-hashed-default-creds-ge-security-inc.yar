rule sha3_512_hashed_default_creds_ge_security_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge_security_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c120e450fdc7ed75ffc85ef2058e7fdf19238d36879ca8704043ce1d356e9df3700ef2ca99cfa258274b181b2f0b10e9cd94ce28305b06dda78f19990d1db043"
    $a1="c120e450fdc7ed75ffc85ef2058e7fdf19238d36879ca8704043ce1d356e9df3700ef2ca99cfa258274b181b2f0b10e9cd94ce28305b06dda78f19990d1db043"
condition:
    ($a0 and $a1)
}