rule sha1_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f0b13fd60474c1b51d583155e86d1ed060dd06f"
    $a1="ee667e187bbecb85b4985dbef39024db3a10d7ad"
    $a2="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a3="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a4="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a5="343bb057273a08674e19f82fbe8ebb6eb8711f00"
    $a6="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a7="9e3721643797e4d1373cfec0d0df4fd7577b195b"
    $a8="9f0b13fd60474c1b51d583155e86d1ed060dd06f"
    $a9="9e730dd02252f95157f9ca559a5a913832d3f598"
    $a10="e888dcac32ac047dd3622a756c4c1e2c9b293858"
    $a11="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}