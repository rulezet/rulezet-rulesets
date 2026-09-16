rule sha3_512_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b726245d7aa6db40f13b117520c88ba2ef50297772e4166c67d92f9f9ad80eef5bb77d85932fcc5c5ca98da4ef0e1bd3cc6fa52594630b9ef0b39c4d4f1fe92b"
    $a1="b726245d7aa6db40f13b117520c88ba2ef50297772e4166c67d92f9f9ad80eef5bb77d85932fcc5c5ca98da4ef0e1bd3cc6fa52594630b9ef0b39c4d4f1fe92b"
condition:
    ($a0 and $a1)
}