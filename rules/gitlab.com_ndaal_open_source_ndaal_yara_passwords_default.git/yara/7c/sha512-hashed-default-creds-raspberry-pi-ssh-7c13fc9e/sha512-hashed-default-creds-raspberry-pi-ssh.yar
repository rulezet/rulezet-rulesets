rule sha512_hashed_default_creds_raspberry_pi_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5895bb1bccf1da795c83734405a7a0193fbb56473842118dd1b66b2186a290e00fa048bc2a302d763c381ea3ac3f2bc2f30aaa005fb2c836bbf641d395c4eb5e"
    $a1="88138504e31a2ba7bd240aed179e436a668ae3e8b4b2b59bcea41f5e012a4528f902fea3bb6bd62a31621497a6efa531241d18da27e07e3fd21ee1e64c2516ce"
condition:
    ($a0 and $a1)
}