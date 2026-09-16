rule sha256_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50cb3d000873ec971dad66e68eccda26db73d5d1508e3a2a5e455451350061d5"
    $a1="73cd1b16c4fb83061ad18a0b29b9643a68d4640075a466dc9e51682f84a847f5"
condition:
    ($a0 and $a1)
}