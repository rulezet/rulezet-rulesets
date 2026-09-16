rule sha3_512_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5438403acc583e941b479bf65876dc3efc1c3c0d200568dfe7daaa7b023832f261e8165d17837a6af4c6f5dcda0b99f25b63c2ef29d46e6e6fa135f8770b0104"
    $a1="5438403acc583e941b479bf65876dc3efc1c3c0d200568dfe7daaa7b023832f261e8165d17837a6af4c6f5dcda0b99f25b63c2ef29d46e6e6fa135f8770b0104"
condition:
    ($a0 and $a1)
}