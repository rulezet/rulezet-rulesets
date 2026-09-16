rule mysql323_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ec171f20aef068e"
    $a1="7891ef712633df41"
    $a2="0208faaf411675cf"
    $a3="43e9a4ab75570f5b"
    $a4="1ec171f20aef068e"
    $a5="43e9a4ab75570f5b"
    $a6="6c986ac36a448ba5"
    $a7="31563c0a19953d16"
    $a8="43e9a4ab75570f5b"
    $a9="43e9a4ab75570f5b"
    $a10="1ec171f20aef068e"
    $a11="58f7ee435f925abe"
    $a12="297432c65fa13086"
    $a13="7a62673526be536d"
    $a14="33ec930f2369c4cf"
    $a15="4077eb0b03ddce3b"
    $a16="452c15e815ade654"
    $a17="0a1838273cbc9961"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}