rule sha256_hashed_default_creds_raspberry_pi_foundation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_foundation."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e97407735e49029c96e5708c724fc9ce57b6335dba804a893320fcb7c0a07953"
    $a1="85b42e1702877c851eb7412fe958c8fb447c3207b4798fadab42ea8539046ce1"
condition:
    ($a0 and $a1)
}