rule sha256_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5838045ead07714510f1176841229b3bebecdbc05a1abfc960ef204092207e03"
    $a1="620933380d886ff848bab95aee5569024a166cfd13293aa8a33aae52d4569643"
condition:
    ($a0 and $a1)
}