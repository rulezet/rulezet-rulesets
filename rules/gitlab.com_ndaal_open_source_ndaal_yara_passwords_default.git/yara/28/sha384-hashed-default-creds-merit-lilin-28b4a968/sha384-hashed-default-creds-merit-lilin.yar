rule sha384_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="100586458d6a8325e05333bd3070b7fa5bf249f1f1f345d7e62efb6ed43c4869b3a550cf2e5af0ad2a448ce03f81b018"
    $a1="c9bb026564ac27e5cc98e0ea41244591470dcc8b0d8e89006c68090a17634f7242112b20b5b109eb460e6a6a6e258f1c"
condition:
    ($a0 and $a1)
}