rule sha3_512_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09a56f64f8710eb25238d72a7f0733f1794ec8e15b94a09292173103f10bf8cadcb07c026c09034f901ed4a461b5ef6bfa359545890bcdf89f4116df22e0ca2b"
    $a1="09a56f64f8710eb25238d72a7f0733f1794ec8e15b94a09292173103f10bf8cadcb07c026c09034f901ed4a461b5ef6bfa359545890bcdf89f4116df22e0ca2b"
condition:
    ($a0 and $a1)
}