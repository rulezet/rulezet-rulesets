rule mysql41_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6691484EA6B50DDDE1926A220DA01FA9E575C18A"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*3D5B8D67927F4A2E700FB064CFDFB3782DB314E6"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a7="*DA7B25B1BA72C91D124FAD86067FE077C0D8F5B8"
    $a8="*3DD53704FFD8E6BBEEA51437F46D13FBCA2FFDB4"
    $a9="*3DD53704FFD8E6BBEEA51437F46D13FBCA2FFDB4"
    $a10="*FD6C4E7782F5B03F2C923C345BB19E47AD530DCC"
    $a11="*FD6C4E7782F5B03F2C923C345BB19E47AD530DCC"
    $a12="*AEB59784B985CE3167B371CA645C86111AEC20E0"
    $a13="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}