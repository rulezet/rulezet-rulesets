rule sha256_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c7853e3659d1c01e65f3cb460ac07d079288bfa5bc21aae3d31fe01a0814278"
    $a1="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
    $a2="cfe6a1d191f7f64b15734bc6a54ae10deedc0c5df936ce1ba2b48ec117112e49"
    $a3="a942b37ccfaf5a813b1432caa209a43b9d144e47ad0de1549c289c253e556cd5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}