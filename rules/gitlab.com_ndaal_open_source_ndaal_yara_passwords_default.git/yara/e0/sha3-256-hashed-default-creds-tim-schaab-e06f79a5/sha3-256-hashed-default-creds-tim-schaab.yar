rule sha3_256_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="043a4b3192fa16dced3d44a0421d1071430738d7b6a109d1a661887f611523ea"
    $a1="5e527ee31f3db0c0dd623164db1faa602ed6fb418a1e1938883bd315c1bbeae0"
condition:
    ($a0 and $a1)
}