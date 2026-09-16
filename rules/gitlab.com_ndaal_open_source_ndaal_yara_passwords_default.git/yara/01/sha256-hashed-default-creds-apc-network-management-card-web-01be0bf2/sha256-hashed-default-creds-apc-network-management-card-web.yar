rule sha256_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a1="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a2="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a3="263a4dbe41488fb87214b0032339dbb9f0c8da14c16dfcf13084bf3c2552eca5"
    $a4="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a5="8171bacf32668a8f44b90087ad107ed63170f57154763ba7e44047bf9e5a7be3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}