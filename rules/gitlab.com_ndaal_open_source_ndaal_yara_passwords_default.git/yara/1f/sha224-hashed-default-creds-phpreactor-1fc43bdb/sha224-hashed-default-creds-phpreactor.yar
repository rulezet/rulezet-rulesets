rule sha224_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="51aa380f70edeeecc838bd278ae78ea707653f2ab7a79d944b8b548d"
    $a1="643fc30d6d77ee255aaa29b84211b518a49e85b3d30e458ca812e361"
condition:
    ($a0 and $a1)
}