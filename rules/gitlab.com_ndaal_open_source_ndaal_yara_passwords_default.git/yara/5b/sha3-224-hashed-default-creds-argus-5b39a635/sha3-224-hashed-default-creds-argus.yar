rule sha3_224_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65a8b6efd24734f6e40cbfddad07491caab5ef3ec7f783df05aa1f7c"
    $a1="23b439bd6beba63f0212d717dad0449ad1bb54a1d100e2f7e3992387"
    $a2="f126332a9852d17e79a05018762b73e18f5a422576d38a5ec91907bd"
    $a3="f126332a9852d17e79a05018762b73e18f5a422576d38a5ec91907bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}