rule sha512_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4fe2742c36544a0c483660f3cab4f97f9b03fc2f4b7d96e9a6b0b7537065ce365cf75f9b18b98223adfa01a46bc30991a2fdbad658614b722edd82a9cac8385c"
    $a1="e7876299a40d476be39c097fc84dac39c8e745fb41391ca929bbf17d749f564576795535290c1737114dc31d9f71db191b1125c403d9de269e2280183dd566cb"
    $a2="9ffa0289047df18fc8f3a0873a5084b42ea4d21f37dd6b6063dd838b052b2f7d5c9a4f7f4b776d1628a63f39b1b5448d665ce445b200f3b40ec8a69f7556b71b"
    $a3="41efd98e07e0cb762fe8c50af1ac78c31301b6403b5569504b4b24bb695a4834202e3a5c3b59c7da4e3ee1f349b8a9e0dfe1ba656927b0d261a44204f2d21c19"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}