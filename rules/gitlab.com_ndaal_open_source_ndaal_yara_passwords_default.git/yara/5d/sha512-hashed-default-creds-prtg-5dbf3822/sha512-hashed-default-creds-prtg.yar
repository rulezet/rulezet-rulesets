rule sha512_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5bb77f3869a5bfd11a256691717ffdccdbbbc8e83caa2ae4be1322fd82e649820f034ea4aa7583bbeef31aaf65948a3dc331375eca4da2dc13fbc7cdb7cb7256"
    $a1="5bb77f3869a5bfd11a256691717ffdccdbbbc8e83caa2ae4be1322fd82e649820f034ea4aa7583bbeef31aaf65948a3dc331375eca4da2dc13fbc7cdb7cb7256"
condition:
    ($a0 and $a1)
}