rule sha512_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb92ec62d0f3d2831dda19a17a3dcdd51b3be8e595ff960e99d424858183f474efa296de95562286abb1c7eb61e38e601bf8ee2d66202713259a68c24d572443"
    $a1="04005c3bd5db18346b7db0a7ff9f4005945c4334496efe87654645451ad395912617b29cb68e864af2ceb7719e08e330e919c2d3f5dd16fe08e9666c9b77562b"
condition:
    ($a0 and $a1)
}