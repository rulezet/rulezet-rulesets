rule sha512_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52e5c5bc0f9511d4bdb9d6626c913bd1fdf13a8e5e6914b148b86886f3dcd7a23bc27896f86b9a009036fbad55158ba7e329433406d84ab45973b451e27d6a62"
    $a1="45fe64d53670a60a32fd45fbeb8e22c2505278209fce59c97212e22c309fb047632305ab94e13afca1e7ddb44da2869c6f5d01ef9010604b74ef24e5921edbc9"
condition:
    ($a0 and $a1)
}