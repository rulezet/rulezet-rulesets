rule sha384_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d61ab9c533623038e3f3fe716e6bac41a554d68dd4539aad767d179f3765b920309c1982e1c6896c303cd4b021ee52b"
    $a1="94833b9499a681bf49149832839a81e40b1b3d7cc0f61f0ebc52ee8483fe6c2e4727b4aeb83c147bffec4ef628996ac3"
condition:
    ($a0 and $a1)
}