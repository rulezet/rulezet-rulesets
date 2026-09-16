rule sha3_224_hashed_default_creds_lockdown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lockdown."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c77f27961e55a7709ed0f910fe9ebf92908f15612bec3536ec8ba50"
    $a1="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
condition:
    ($a0 and $a1)
}