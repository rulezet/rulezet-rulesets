rule sha224_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f13509df7748da4564145a66d4f7e30313a4cf0be791d98c344301e8"
    $a1="f1f21ea3df92906c45090ef120acd534336ee4f9ae440eaefcf6b0a9"
    $a2="f13509df7748da4564145a66d4f7e30313a4cf0be791d98c344301e8"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}