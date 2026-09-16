rule blake2b_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8667f3c9befe7ad58db777ab8cf7131ea08c00517b9ee70e00da37f4f88f56e8b001382885b517a363bd5117ec7cf74fa4305ad18e8773e76ee5176a77695187"
    $a1="8667f3c9befe7ad58db777ab8cf7131ea08c00517b9ee70e00da37f4f88f56e8b001382885b517a363bd5117ec7cf74fa4305ad18e8773e76ee5176a77695187"
condition:
    ($a0 and $a1)
}