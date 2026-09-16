rule sha3_224_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
    $a5="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}