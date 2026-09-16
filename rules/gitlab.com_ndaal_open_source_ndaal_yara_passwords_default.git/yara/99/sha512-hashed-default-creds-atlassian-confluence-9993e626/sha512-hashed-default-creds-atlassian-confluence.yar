rule sha512_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f702ad80f98e203afef19b63198a9c3a1ac573b8bfc495707aa663a33241a90bfde469cbd31984f1eb39fd18b8353241b9ead7a4047139e319720c2f7695f79"
    $a1="0d54d4b86f7c106b098611d0837c4663e619d24284772e6945484c5b0061c32ea4a3d7784b12308cac155cc93e55a9b3f535feb613f8d6cba942ab713b2637d2"
condition:
    ($a0 and $a1)
}