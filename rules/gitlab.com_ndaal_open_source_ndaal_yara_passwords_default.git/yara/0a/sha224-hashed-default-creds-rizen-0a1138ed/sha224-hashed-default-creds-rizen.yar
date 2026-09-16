rule sha224_hashed_default_creds_rizen
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rizen."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c878bad891987c11278e891a197c708c484242d32c701c7d72c0f245"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
condition:
    ($a0 and $a1)
}