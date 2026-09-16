rule blake2s_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d1301d264ca4b80b488d1785349ebe7e9cab4f7ce4866c5c2ee7870986a2a79e"
    $a1="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
    $a2="a3866d06cdac0a0e9d7286439fa10193cc2f8a9991444dff01a5c1b8955ee428"
    $a3="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}