rule ldap_sha1_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}x45HZ1Hua9AFbZ1cbGuVliR4TvQ="
    $a1="{SHA}DPEkM3mSa/gPMInYKdp49gUnbOo="
    $a2="{SHA}yxYK47CnhSHBrRnSLH0F5N4MWqc="
    $a3="{SHA}yxYK47CnhSHBrRnSLH0F5N4MWqc="
    $a4="{SHA}i28VmbPpgZQMKFyPOqY/XWW/qzM="
    $a5="{SHA}i28VmbPpgZQMKFyPOqY/XWW/qzM="
    $a6="{SHA}RVozMAS9P/oZngghidenQfHrWk4="
    $a7="{SHA}RVozMAS9P/oZngghidenQfHrWk4="
    $a8="{SHA}RiSW4mKnRmkJ1MlqHRztlyKexio="
    $a9="{SHA}RiSW4mKnRmkJ1MlqHRztlyKexio="
    $a10="{SHA}xFE4nRWjpTSdzvHxwD4Ehc6+hxU="
    $a11="{SHA}RiSW4mKnRmkJ1MlqHRztlyKexio="
    $a12="{SHA}a/SdfCNBKcJgDUxwsCNPTgNqiSw="
    $a13="{SHA}RiSW4mKnRmkJ1MlqHRztlyKexio="
    $a14="{SHA}/th+Mi2i0wVYTA5YAFJaBSm/JB0="
    $a15="{SHA}RiSW4mKnRmkJ1MlqHRztlyKexio="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}