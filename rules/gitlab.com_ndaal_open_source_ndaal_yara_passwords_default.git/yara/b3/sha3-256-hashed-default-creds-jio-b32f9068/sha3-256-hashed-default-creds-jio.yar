rule sha3_256_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fc08d44dcbdf52eef0187330b67cc5fe1b2e9ea8b2bf7a96eb648ba706d626a"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a3="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}