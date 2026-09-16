rule sha384_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="288ce6530319077f60476ac0e066c777c5551c67dacdb48af81cc65aa09adb3622e4ec3bcc495487094ef3442bb98602"
    $a1="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
    $a2="f87c1ebc04f901041f18dfb7d24bebc6d45e1cbbb2d9f005605e47afbc6d5d56356e3ee5f7762c5373219eb2ffd6554f"
    $a3="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}