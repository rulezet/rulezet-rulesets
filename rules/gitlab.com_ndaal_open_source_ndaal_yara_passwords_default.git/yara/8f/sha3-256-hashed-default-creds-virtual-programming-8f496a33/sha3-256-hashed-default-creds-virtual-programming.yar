rule sha3_256_hashed_default_creds_virtual_programming
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for virtual_programming."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="0bf71ffcfa408f0f5ee5c456e0e5f07314f12a225ba5e1404f4298265405af45"
    $a3="0bf71ffcfa408f0f5ee5c456e0e5f07314f12a225ba5e1404f4298265405af45"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}