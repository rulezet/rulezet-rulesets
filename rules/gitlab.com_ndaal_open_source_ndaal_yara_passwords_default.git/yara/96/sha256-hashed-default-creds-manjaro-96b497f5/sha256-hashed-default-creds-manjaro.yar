rule sha256_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80c7d61e5b4fa27be3b32b00705b5386648eb09faa5876f958c18fa11beec342"
    $a1="4df87556ebc9fe46c1eef23662f6787f855c788d09f61dec25eb9f422fa0d3f7"
    $a2="d0711a9964cbbeb11d992fb183ba18dd9db3b71b8604f67cdfcb127af02b3af4"
    $a3="4df87556ebc9fe46c1eef23662f6787f855c788d09f61dec25eb9f422fa0d3f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}