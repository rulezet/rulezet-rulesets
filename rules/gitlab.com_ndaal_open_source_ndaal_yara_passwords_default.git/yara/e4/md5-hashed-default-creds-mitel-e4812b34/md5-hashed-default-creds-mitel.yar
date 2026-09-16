rule md5_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="54b53072540eeeb8f8e9343e71f28176"
    $a2="a9b7ba70783b617e9998dc4dd82eb3c5"
    $a3="97384261b8bbf966df16e5ad509922db"
    $a4="2b351bbc06a1506a8777cc8c66518540"
    $a5="54b53072540eeeb8f8e9343e71f28176"
    $a6="ac7b4dfe519da7960eb27b98f8780a9f"
    $a7="97384261b8bbf966df16e5ad509922db"
    $a8="62181d1bf72f6deaf2fa61130c72bb0e"
    $a9="54b53072540eeeb8f8e9343e71f28176"
    $a10="3d2172418ce305c7d16d4b05597c6a59"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}