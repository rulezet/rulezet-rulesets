rule nthash_hashed_default_creds_hemoco_software
{
    meta:
        id = "3YUJ3DjqehuRUtLpJnvjQw"
        fingerprint = "733719f594a81d07965a8680ff56fa713c0b51decd942145005a67b22e47bb13"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ec8c90a4816d4986cf457393071dda14"
    $a1="1c6abf437c36b1047a8b81993f775102"
condition:
    ($a0 and $a1)
}