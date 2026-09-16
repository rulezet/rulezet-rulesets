rule ldap_sha1_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nB1sz3orMWex2yVY5SV1EGusWmo="
    $a1="{SHA}fNClDvYBSHnP5sbrrhYP7lOzP/0="
    $a2="{SHA}t4MfIC7mxWK4Nz5M05e9ESwaHwY="
    $a3="{SHA}Cn/Fh2uxQG9OtMkln57dnDMKYnM="
    $a4="{SHA}9cg/eTlkCtTcC2foWLsbKspe40k="
    $a5="{SHA}sYA2YLCb5HCG0FkE8VwtoKFqIg0="
    $a6="{SHA}oyYX0xwn8pf/3JSgWYE3SV+Dtb4="
    $a7="{SHA}kWABfXhhhR2VJsx3WzpPLAOcnQQ="
    $a8="{SHA}Q7/21c2I2gG8cEZtSHWmXq+sK2k="
    $a9="{SHA}2YhLgGgsx9w6edTsoLbwmKSNMJE="
    $a10="{SHA}49YcfRbPqymA3u/QT+z669FBcj4="
    $a11="{SHA}zNqECQInWpx+6MHGoXnRHnXeziY="
    $a12="{SHA}addumwLQq+hfxj5lilxIH1B1vBI="
    $a13="{SHA}sA3LKJTRi5p5FZXjFnrem/rkc8Y="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}