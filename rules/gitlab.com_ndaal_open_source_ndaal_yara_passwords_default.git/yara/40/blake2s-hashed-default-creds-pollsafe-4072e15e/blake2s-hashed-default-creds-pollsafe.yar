rule blake2s_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecb70a7762ae4de51ade8691dbd617e30da39e05a2a739ff3a48aeeb524eed25"
    $a1="7e362c8c3cdff8ae96a6cab56544ca0692349dc9c88a54855f042df1fc9190b4"
condition:
    ($a0 and $a1)
}