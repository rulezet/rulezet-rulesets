rule ldap_md5_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}sti7SST1m3HAaWDge/yj+g=="
    $a1="{MD5}bf9k76+WP7+T2s798zmG2w=="
    $a2="{MD5}sti7SST1m3HAaWDge/yj+g=="
    $a3="{MD5}Z3lemCKfAEpC1D1c5i0Afg=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}