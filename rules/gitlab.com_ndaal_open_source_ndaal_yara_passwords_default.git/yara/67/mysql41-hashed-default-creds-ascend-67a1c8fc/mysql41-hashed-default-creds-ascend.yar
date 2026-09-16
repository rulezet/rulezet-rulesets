rule mysql41_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*06D52F7D03663CBCAB6ADB48D1F757632FFBDF52"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*F41EB78C5190F200941114EA9A846EA7C8660866"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*78FB7C5D32AF903AF5905FFD2484ED91A31A4A29"
    $a5="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
    $a6="*04819F91FA44D553D301CA7F7CE3848BC3053BB9"
    $a7="*FC4C8052E3C11C2C1FBB16180EFFFC36869B177E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}