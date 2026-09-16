rule sha3_512_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef7e5953feeb9588e6916882e26695aff6cea2f442556bc25bc6603a95fc5efc1e58c6573edf215d296ee93a325925f7ee32eb64cfdf274be7670bdfe5d600a4"
    $a1="21615caf63a7252caecd365b3e538fb27a66bf184a1d0f79e2081eea0e03d5ab3b1e232e8d8295bd7aa06cfd295900f65004c55dc9e37a7a56c812293dd78fb6"
condition:
    ($a0 and $a1)
}