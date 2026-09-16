rule sha512_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e1c00887d820074eb1ff6971ef581715e3c18c75f1b43f5786b6d6c45798286d39176d2d75ec392d65ecb1b059c385a1c73719cbe634f352098c3a9b94cb2b1"
    $a1="0907d458d75760dc66e4add0227e76af23b8234fc35ac908673f847e13fe51192a8673b9a818af4c12d53904ca1e707c69fdd856a1f716e864f18ad32ed64978"
condition:
    ($a0 and $a1)
}