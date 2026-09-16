rule sha3_512_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b956247fe139c97ca596ff757166efedf599a6cca9e0aee1ded270926301652bf277f74ff8eb3941cd0958947f86b2e94b5205bc1c104fb10ed9ee763028d36d"
    $a1="13b03cd2ef924d74d9634aef0a55fed48e6c2a51919b0492bd0bbad877c90ed0c0f06cc86a913b49e99e0bc3dfc47e65063a96cd9b09232fc9f19be4a6d55a22"
condition:
    ($a0 and $a1)
}