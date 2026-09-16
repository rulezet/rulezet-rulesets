rule sha3_224_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db8be03ad95b60db24a1b3ab1492a48bc3bbf9f6fcacbe79fc70efcb"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="ea97e30a08153a029bbcbc81f26dc49de73ee31dfa70c494acf66233"
    $a3="ea97e30a08153a029bbcbc81f26dc49de73ee31dfa70c494acf66233"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}