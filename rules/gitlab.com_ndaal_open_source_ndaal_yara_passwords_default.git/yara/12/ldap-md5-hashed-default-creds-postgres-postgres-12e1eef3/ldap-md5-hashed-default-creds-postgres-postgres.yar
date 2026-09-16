rule ldap_md5_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}vtEoNlIWwBmYiRXtOt11+w=="
    $a5="{MD5}PTZWKJnDiKftnEDcXC2/Bw=="
    $a6="{MD5}ICy5YqxZB1uWSwcVLSNLcA=="
    $a7="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a8="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a9="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a10="{MD5}WVSJdyeZBSNLftOxcQg38g=="
    $a11="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a12="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a13="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a14="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a15="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a16="{MD5}htDrm09IPDb9SPypEhG1sQ=="
    $a17="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a18="{MD5}+J8STAsjC+lVfHFJEu4zIA=="
    $a19="{MD5}6KSGU4UeKMadBQZQj7J/xQ=="
    $a20="{MD5}+J8STAsjC+lVfHFJEu4zIA=="
    $a21="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a22="{MD5}Jd8xBMDW8MGr2cl79pEHcQ=="
    $a23="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}