rule sha1_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a4="71741899f22a00c72ee4f74c613470664b6e241c"
    $a5="71741899f22a00c72ee4f74c613470664b6e241c"
    $a6="62fdbe21cf61f637191d971ab9a5caba51094aa7"
    $a7="10ffe60d53e7703286eaab421f05c946ffa19a37"
    $a8="b6497a0ad71538443248bde3420cbbda395fde00"
    $a9="12dea96fec20593566ab75692c9949596833adc9"
    $a10="12dea96fec20593566ab75692c9949596833adc9"
    $a11="12dea96fec20593566ab75692c9949596833adc9"
    $a12="59836eac64195796688a11780df5c4e2ce668b95"
    $a13="59836eac64195796688a11780df5c4e2ce668b95"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}