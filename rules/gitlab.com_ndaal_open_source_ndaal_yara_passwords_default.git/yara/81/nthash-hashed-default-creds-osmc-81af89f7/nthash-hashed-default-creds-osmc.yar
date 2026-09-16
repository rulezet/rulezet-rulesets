rule nthash_hashed_default_creds_osmc
{
    meta:
        id = "1OFDM2Ojzq2NO0VP04GBQj"
        fingerprint = "801f89efa567fcdc8d08b25ea04dd233adeba9d1d674cceeffb979f46bd39b98"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b9bb5b606ffd46c8d1bf9c592ec1808"
    $a1="2b9bb5b606ffd46c8d1bf9c592ec1808"
condition:
    ($a0 and $a1)
}