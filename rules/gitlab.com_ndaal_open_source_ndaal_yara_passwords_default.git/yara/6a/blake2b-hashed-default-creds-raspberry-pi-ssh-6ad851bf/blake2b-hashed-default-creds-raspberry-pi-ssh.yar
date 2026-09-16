rule blake2b_hashed_default_creds_raspberry_pi_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cc17a49898d6d401b4f63b96ea62e24ca798f59c3aa54b57f92d2f5df455ec17166423287d368980f102d3144f2f38f0b570bc0c13c835de32c00bcb72728f8"
    $a1="d6e1f63f0278cad56cc49fd8bf2ee999351369561a78c6c617ce11ca97a367c2ac8e2ac1ed2fdac6517980ee2b5a975fd5f484d301b7681618321e4d9d47e2e8"
condition:
    ($a0 and $a1)
}