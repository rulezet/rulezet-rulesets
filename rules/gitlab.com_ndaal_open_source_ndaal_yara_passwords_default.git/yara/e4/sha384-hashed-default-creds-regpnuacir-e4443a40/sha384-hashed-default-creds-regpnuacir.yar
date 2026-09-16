rule sha384_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fdb9c3a439c356436b33762492e8d9a7c2aab1c31f135f1345f71353912b8d7c93321e2dad31941e379ada0fce7d01f"
    $a1="db286047f4506f3b7c2e110b8c0425ece106d769fc0416fc307f2308563a6b510de342840bd0ed18b5a4ce978d8e5bb8"
condition:
    ($a0 and $a1)
}