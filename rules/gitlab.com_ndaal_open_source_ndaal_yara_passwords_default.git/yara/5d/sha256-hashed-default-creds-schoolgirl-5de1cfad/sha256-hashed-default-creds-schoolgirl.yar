rule sha256_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aef0839575127e7bb3eb0c7c574ebc8d9a7163d9a4bca11fbfced360a82ecfd6"
    $a1="84c92d8abf326bdb52f1fc6cd6856c41ae9bc1ef4f6056c2672e3d9d301782e1"
condition:
    ($a0 and $a1)
}