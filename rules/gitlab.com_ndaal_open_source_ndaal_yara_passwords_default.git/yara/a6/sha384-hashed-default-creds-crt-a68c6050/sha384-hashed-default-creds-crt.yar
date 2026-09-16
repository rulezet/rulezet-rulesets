rule sha384_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6292b11d918f502260601e43758bee89204d42c3fdfdb63a4e05aab43447031cca7d8a40b117ba6d71a9d2cb07b19dd"
    $a1="bb4fa1e408c1d9a1b46af7126729b13cbd8a01e705bc6e26fc59b2a7de2e90b43991c792c4089438a4473bd5f6fa76cc"
condition:
    ($a0 and $a1)
}