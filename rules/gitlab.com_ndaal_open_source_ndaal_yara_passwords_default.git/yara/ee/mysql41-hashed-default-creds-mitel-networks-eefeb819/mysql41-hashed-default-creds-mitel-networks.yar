rule mysql41_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*700059826CC0D4CA300205D7A323A3D3BE33C840"
    $a1="*5C6FD33285EC724AC66AB0E4B5C6AFB79868C24B"
    $a2="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a3="*432DADB80863E758A32913E510F74D01A605B00B"
    $a4="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a5="*07277821E7C889F93B4FEF93A42209A4E53023D9"
    $a6="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a7="*A3990B70C8593C66B534B148BABBA5DD680D3AE1"
    $a8="*700059826CC0D4CA300205D7A323A3D3BE33C840"
    $a9="*170AFEC341719E6A5EFEBE910A89A3DF26CF5352"
    $a10="*BC2DDFC5FBC0F9FF8A710D57E1FF4FCCF6D6901C"
    $a11="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}