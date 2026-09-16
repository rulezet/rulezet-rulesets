rule sha3_512_hashed_default_creds_airaya_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a773241ecd38f3fc34602c0a58d0d16dd40acba244545e2e93c4edd08b4aca47a2c658206809e04630519efbbceb9a8ffce979c9939f33717fae830431aeb78c"
    $a1="a773241ecd38f3fc34602c0a58d0d16dd40acba244545e2e93c4edd08b4aca47a2c658206809e04630519efbbceb9a8ffce979c9939f33717fae830431aeb78c"
condition:
    ($a0 and $a1)
}