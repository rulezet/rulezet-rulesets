rule md5_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca59c2cb9f3382bdf41114b7374c6171"
    $a1="ca59c2cb9f3382bdf41114b7374c6171"
    $a2="bc4309b926172bf7f180eeaaf2db6002"
    $a3="87f64d5c0cc348bf47cd17c911f4396f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}