rule sha224_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11e2102bd17c2b108cd82ac199ff29dfc9efe64ea3ebb652957ab9f3"
    $a1="11e2102bd17c2b108cd82ac199ff29dfc9efe64ea3ebb652957ab9f3"
    $a2="1313c0b3d86759d4ba1e8dad80c91963d876649017788eb264bfe0ea"
    $a3="a7860cb07d533157c51cb22c75cca370bc8a96dcfe6d17bfb39ab588"
    $a4="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a5="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a6="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
    $a7="9770983b66e595f0ba5f261161c1ae7847064a4a3a4ad7791510733b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}