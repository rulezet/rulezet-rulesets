rule sha3_224_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23043cdd8a5e13150461e02a1103c3c8b030a16ff727e2656a58251d"
    $a1="23043cdd8a5e13150461e02a1103c3c8b030a16ff727e2656a58251d"
    $a2="301a0bfd98045e96b6bc5a8897808683bb6c5c7e8ca92b65fa75945b"
    $a3="109bee661dbc08cb30bb6dafd648ebce86fd7d00d39594e47b560182"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}