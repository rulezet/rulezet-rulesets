rule blake2b_hashed_default_creds_osmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74ddf5061180e757b1d6e52b8247c6723cd3beba3ad39f606611c46a42acb48258e86df477eb699d8929e7d6d8b32f42339b5bd3f20942f042463e8224810405"
    $a1="74ddf5061180e757b1d6e52b8247c6723cd3beba3ad39f606611c46a42acb48258e86df477eb699d8929e7d6d8b32f42339b5bd3f20942f042463e8224810405"
condition:
    ($a0 and $a1)
}