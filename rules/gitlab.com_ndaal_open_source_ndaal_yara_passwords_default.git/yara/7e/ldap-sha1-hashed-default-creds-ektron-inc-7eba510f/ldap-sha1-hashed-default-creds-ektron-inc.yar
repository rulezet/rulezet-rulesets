rule ldap_sha1_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}dIozbMiMA8ywftX1Bz0YYkcxuLU="
    $a1="{SHA}dIozbMiMA8ywftX1Bz0YYkcxuLU="
    $a2="{SHA}VPObKwlxkMf4F9CbcYmdscn+v10="
    $a3="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}