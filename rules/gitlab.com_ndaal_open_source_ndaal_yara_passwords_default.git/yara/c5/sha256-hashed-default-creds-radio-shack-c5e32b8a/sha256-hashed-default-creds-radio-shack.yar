rule sha256_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a15faf6f6c7e4c11d7956175f4a1c01edffff6e114684eee28c255a86a8888f8"
    $a1="43f98918052bdb9677a20185bfdc04f5bc3d2d9f2c686f1bdfbc399b5a4fda89"
condition:
    ($a0 and $a1)
}