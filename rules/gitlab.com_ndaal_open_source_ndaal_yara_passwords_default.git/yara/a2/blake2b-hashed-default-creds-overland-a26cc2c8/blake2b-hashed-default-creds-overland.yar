rule blake2b_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6554dad708a65bd7d3abee2d9c028e2e4c1319fb3ef8a752723b70afd572dfc408d3b1d0d19950f280d8772012d0a35209f5546345c3be1d3367fa34e9bb1e92"
    $a1="ef3c14a1d14912c2dbc35856ee8d08de8b5cd143f8f2a1b8c236f7ef846756e630803fe34243cf58aafa705e03a99d688ea1985a116ad0d1ee2dacf364e3faf1"
condition:
    ($a0 and $a1)
}