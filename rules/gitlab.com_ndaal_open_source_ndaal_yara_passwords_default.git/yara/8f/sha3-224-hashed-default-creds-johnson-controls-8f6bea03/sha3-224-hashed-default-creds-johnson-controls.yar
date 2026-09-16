rule sha3_224_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcb990d7e2300a10dd151103bc92f4a2ed4ef48e7d0e033504da8cff"
    $a1="6ca32d3ec254ccc030a275f34dbc98c5c4b80ba402dcfdb7fa32be5f"
condition:
    ($a0 and $a1)
}