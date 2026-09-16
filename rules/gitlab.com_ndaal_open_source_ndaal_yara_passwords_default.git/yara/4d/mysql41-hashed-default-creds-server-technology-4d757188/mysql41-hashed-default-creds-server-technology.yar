rule mysql41_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B451FD8C3F3CF3D58F0D234B41D03CD3D5EF1D17"
    $a1="*74D4164586CB36D11226A78A9D7D1ECF19CFD48C"
    $a2="*3DF08C86B790C14ED38E6ED034F9E64DC2879CAD"
    $a3="*ED36E3B39C24A94CB32B9E292AAB1F1298FA8028"
    $a4="*C6690B1409443F9A929FF78B8ED5D2B05A582B52"
    $a5="*E86EA73687793BE0FC3C346CAB177815E3402BEC"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}