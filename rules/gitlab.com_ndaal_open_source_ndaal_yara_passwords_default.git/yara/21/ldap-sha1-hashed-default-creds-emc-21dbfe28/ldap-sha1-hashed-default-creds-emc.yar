rule ldap_sha1_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}KSzi/COlnp0ojlbsvJn94ZyFse0="
    $a3="{SHA}cVo5hbOXSoLeKqXuSNcHpyDDJWY="
    $a4="{SHA}7/0r/LwDkOQ3DgZl2YQe+k8YrFk="
    $a5="{SHA}WI16qbupT+vW5NEyUdvpc0TJBcQ="
    $a6="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a7="{SHA}0tcQ+UtSBdNent0LDZFNycn3DOc="
    $a8="{SHA}wLluvb1Gf0gu9qAmg22L7KXzoKY="
    $a9="{SHA}EzkNcdMmNvZd0Wh39j5uiYG+HVc="
    $a10="{SHA}QXVK91l4PjhJHXGcw/HB1e30boI="
    $a11="{SHA}JL9KgCYlDOqUOTZSKbXPUVJMh9o="
    $a12="{SHA}5BNMDBtATbIBUc8gW4wWoos+FKA="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a14="{SHA}+pvrmeQCmtWmYVOZ57uuITVghrM="
    $a15="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a16="{SHA}qMUPtuSIL4tq6Fkwjhv1+xDol/Q="
    $a17="{SHA}KhdeIjK3SF1tYRa8S/3Npy0mS6I="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}