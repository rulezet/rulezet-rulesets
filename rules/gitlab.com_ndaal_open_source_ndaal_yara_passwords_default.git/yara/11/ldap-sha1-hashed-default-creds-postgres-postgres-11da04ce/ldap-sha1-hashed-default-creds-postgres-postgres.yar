rule ldap_sha1_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}fGphxo74ubawYbKMNIvB7Xkhy1M="
    $a5="{SHA}ncvRrtFTGA2WpJDOVPTRNQiUBtM="
    $a6="{SHA}QL0AFWMIX8NRZTKeof9cXsvbvu8="
    $a7="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a8="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a9="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a10="{SHA}70v9Hm0nj2vH1KR48Cviy5WBoKU="
    $a11="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a12="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a13="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a14="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a15="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a16="{SHA}PRnMKXnRpXf5Y4+vQ+/GOfPkWqo="
    $a17="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a18="{SHA}Xy20zPFMhh9AbmeMTF6w5FBT9gQ="
    $a19="{SHA}r8hIwxavGonUmCbFrp0A7XaUFfM="
    $a20="{SHA}Xy20zPFMhh9AbmeMTF6w5FBT9gQ="
    $a21="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a22="{SHA}LqaEIGkPqURNr4OmjJu/JJp77Qw="
    $a23="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}