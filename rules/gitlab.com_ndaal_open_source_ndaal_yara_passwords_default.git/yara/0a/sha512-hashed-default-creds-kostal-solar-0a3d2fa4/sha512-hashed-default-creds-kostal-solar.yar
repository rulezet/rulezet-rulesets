rule sha512_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc93605408e390e4fa85253e2bce6e61157dfbbdaec277cc44a80ddaadae9ca16fd240000b3f830b808748cff8cfb16eaf7c1ee29f8589abb24d94232c7218f7"
    $a1="81d6668f1049d365d9b7b5db82e20231882afe5c999818df3496d4e2406bc5f631ffdb52b5e511b3578aeec7dfebb63d967e3c542f6ae9d29427014572a87de8"
condition:
    ($a0 and $a1)
}