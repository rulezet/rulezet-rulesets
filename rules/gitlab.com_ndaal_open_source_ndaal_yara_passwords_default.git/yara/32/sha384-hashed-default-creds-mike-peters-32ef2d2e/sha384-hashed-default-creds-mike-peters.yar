rule sha384_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d03678115cd5643b076a0615aa216daa526aaff50953402c0c5d137a3789d55fa5dba8cfcdb76ced557ce0e376b8c31"
    $a1="36606b2a05ac1bf5ec5da128d378fcabf2198e34914fe1f6e14e2238add9dec270cedd11ec57cd75d2f53c14666596b6"
condition:
    ($a0 and $a1)
}