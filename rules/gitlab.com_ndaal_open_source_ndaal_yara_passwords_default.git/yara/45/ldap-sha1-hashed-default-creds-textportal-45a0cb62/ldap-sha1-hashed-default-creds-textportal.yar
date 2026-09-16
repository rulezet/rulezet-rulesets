rule ldap_sha1_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a1="{SHA}CNKLANjCwc5NBmKFfbU8gZGtJKU="
    $a2="{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ="
    $a3="{SHA}U8pMvEKTq5WwVeo1uvMgCoA1gyY="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}