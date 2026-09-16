rule sha3_256_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc84f389af1aba71162a91d93db7651413d64a00b024e5e407719e25b0247f9b"
    $a1="cc84f389af1aba71162a91d93db7651413d64a00b024e5e407719e25b0247f9b"
condition:
    ($a0 and $a1)
}