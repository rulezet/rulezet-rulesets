rule sha384_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fe0f1c1f055bc4a34bd4580790d33fca2b1d00e4438acabd4714ead24133d8bc9eef9bbc3076a7ba7c77a8d4de24798"
    $a1="42f7b954c8874b30eef25102ac15541be58c278ae7679530773268ad7f5ee463da66ab0e7df4e2a84bf983bba379301b"
condition:
    ($a0 and $a1)
}