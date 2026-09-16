rule ldap_sha1_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}9kzY4y9ax1U8FQvQXW8iUrtz9o0="
    $a3="{SHA}9kzY4y9ax1U8FQvQXW8iUrtz9o0="
    $a4="{SHA}CpL6syMBNMym6t2YmDJbmyrmeZg="
    $a5="{SHA}CpL6syMBNMym6t2YmDJbmyrmeZg="
    $a6="{SHA}B7lNzhxfxx4LYuWjQBDmD+nlAwA="
    $a7="{SHA}XWcuzKaDR1rYSbNXgfjiFrdAiMs="
    $a8="{SHA}01UUc2FGQ5tyd0NwFs20DX+2VJc="
    $a9="{SHA}sQwxaYTdFO8QEIJR5AeEDq1t5EM="
    $a10="{SHA}sFdT8tT9R0bnigd4ig/D/0jo814="
    $a11="{SHA}sFdT8tT9R0bnigd4ig/D/0jo814="
    $a12="{SHA}qhmMaAaBGqMbbwelgbhRQgr2oOg="
    $a13="{SHA}qhmMaAaBGqMbbwelgbhRQgr2oOg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}