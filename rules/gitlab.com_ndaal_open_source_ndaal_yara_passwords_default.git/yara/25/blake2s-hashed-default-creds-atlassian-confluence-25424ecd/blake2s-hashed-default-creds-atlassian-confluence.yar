rule blake2s_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e5642e65f89a3fce568ac12ec07e5c480045858c56eccc2192fb1b029bd60b9"
    $a1="bb4ce5e330f57036bf1d873ce9b214373290f1d071421b88eec3840eebb0511c"
condition:
    ($a0 and $a1)
}