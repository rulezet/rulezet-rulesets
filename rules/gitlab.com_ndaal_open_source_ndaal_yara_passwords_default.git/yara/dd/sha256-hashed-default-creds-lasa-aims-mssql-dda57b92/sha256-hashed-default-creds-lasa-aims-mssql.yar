rule sha256_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c7611bc6a334a5ca549c010c57b8340d08bcf14e1af7a28faddcc06ab6536e5"
    $a1="835d6dc88b708bc646d6db82c853ef4182fabbd4a8de59c213f2b5ab3ae7d9be"
    $a2="3c7611bc6a334a5ca549c010c57b8340d08bcf14e1af7a28faddcc06ab6536e5"
    $a3="67719f714cfff1bef08a87c4611ffacfb4cd965e0f049d831ae4389b24f83249"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}