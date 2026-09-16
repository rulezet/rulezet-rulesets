rule blake2s_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a081adbf29d497c40569e453fbd92bae951f59b35b2c8ae475b1d4e08238c6d4"
    $a1="a081adbf29d497c40569e453fbd92bae951f59b35b2c8ae475b1d4e08238c6d4"
condition:
    ($a0 and $a1)
}