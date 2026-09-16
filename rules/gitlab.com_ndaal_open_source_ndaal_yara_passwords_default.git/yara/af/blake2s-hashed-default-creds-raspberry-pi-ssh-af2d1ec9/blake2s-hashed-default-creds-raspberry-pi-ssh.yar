rule blake2s_hashed_default_creds_raspberry_pi_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3384299169959fc6bd5bd77fea881c34b65fe2cb6a1cb6598dd19d9aed142e24"
    $a1="df7237b77fd25a16b214d44d11c5a7c72b17987c1521e33d355ababb23755e10"
condition:
    ($a0 and $a1)
}