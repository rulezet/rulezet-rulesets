rule ldap_md5_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}BI6FEsv9vViThWHEuxaDzQ=="
    $a1="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a2="{MD5}VYGsh2xjg2SrfSAA0dDpoA=="
    $a3="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
    $a4="{MD5}VYmf7y8LLroT6xMWs0s2lA=="
    $a5="{MD5}e3vCUS7h/tzXa9xokm1Pew=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}