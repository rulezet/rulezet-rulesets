rule sha3_224_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a1="86d9551ea8b79b5fbbdf7f69849ba516861b95819051e623e5d9586b"
    $a2="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a3="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a4="cee18a4cb12aebdb494bc2162bd4de85ee82649bc6b30953e6caa5e0"
    $a5="f22db770eeb09733518c60b5db362616dd1f53d547a444db01b25d72"
    $a6="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a7="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a8="ed68a18148be99a8540c20ea3da22e1848451cbf2505c6981f51748e"
    $a9="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a10="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
    $a11="f804285a430337532393e1087b41203956bfbb368077d8beaf513ae7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}