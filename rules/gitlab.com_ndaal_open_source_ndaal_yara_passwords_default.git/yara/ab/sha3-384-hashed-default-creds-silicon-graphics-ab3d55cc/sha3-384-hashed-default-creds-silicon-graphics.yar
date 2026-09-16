rule sha3_384_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a1="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a2="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a3="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a4="8489527df88be00ac879ec53e7e57dfd9d4ee27b0e3a5d8e7a90ec476055efd599ba2a7184ee9d650870e9f5c593a778"
    $a5="8489527df88be00ac879ec53e7e57dfd9d4ee27b0e3a5d8e7a90ec476055efd599ba2a7184ee9d650870e9f5c593a778"
    $a6="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
    $a7="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}