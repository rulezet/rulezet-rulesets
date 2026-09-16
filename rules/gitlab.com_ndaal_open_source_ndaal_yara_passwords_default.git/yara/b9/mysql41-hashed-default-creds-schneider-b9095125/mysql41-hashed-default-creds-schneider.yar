rule mysql41_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*50D8F90CF73E583752F255BC8EF69271A86622EA"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*3667E195CEE710DAD1664BB67EC54BD231116A0F"
    $a3="*0F2ECC6C323671315316386889E116408B996D0F"
    $a4="*FEC7882CC5CED39B7D422835A959FFCC4EA205C0"
    $a5="*CE64E548B5368C3DB66764B2C744B9BB4E15B6DA"
    $a6="*C40D504517AF441DF5F7620932541A322D64387E"
    $a7="*E518C52F0A3A97843278BC14F962395227E52B73"
    $a8="*05B92B9BC77519D2B5D2492FE32792382C5A3D6D"
    $a9="*D7B6822013515EE400D953231633990E9E6B21F4"
    $a10="*197A0CC528020173082687322D7D75EB62270AF7"
    $a11="*197A0CC528020173082687322D7D75EB62270AF7"
    $a12="*F8D6C7DD65A3DCC6330E2D9308CC8602B166E63D"
    $a13="*197A0CC528020173082687322D7D75EB62270AF7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}