rule sha384_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b11a42689ec58f04c80132d9e1bc00269f67ec57f61f95ed937b3d53196b2da17648d67e466e1453d23bfc96398b26f4"
    $a1="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a2="da39e337d7aca91516ebc4d0c96f3549c15be792df607f1cf5885ad30910c19a69743b873e409b54e6b8bcc9db829a3c"
    $a3="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}