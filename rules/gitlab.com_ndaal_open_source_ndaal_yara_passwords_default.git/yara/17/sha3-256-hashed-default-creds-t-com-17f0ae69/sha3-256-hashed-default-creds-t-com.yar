rule sha3_256_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78862c046d1f4decfbb5d328419fc114056968458218e459ca691f77bfe2e901"
    $a1="93512196dfe5353417edb53da86a3feac1527163d07f32af13a9ae30707c48d8"
condition:
    ($a0 and $a1)
}