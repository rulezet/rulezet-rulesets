rule blake2b_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c7ecc957bf227e01fcc0ec710e3dd8df84cadf843e958f34658013216a535e6d6db487386f78792a9e7747b69582fb7f883c44a96de300bac7dee8ae3fa7ac9"
    $a1="2af8151bc3707323d828facb3cdcbf853baf893a5fa46cd03f4382745980fba33183dc43fab77d74a4193202c7ef6b45a07af8b0497b2fc4cb9d7c892b3f7feb"
condition:
    ($a0 and $a1)
}