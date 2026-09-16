rule ldap_md5_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}yMgeNZq6gkLi9luHLixn9Q=="
    $a1="{MD5}j7tl1TQKPambSdpKWE9CvQ=="
    $a2="{MD5}ipi+GVyGwoV8xBha9T48hg=="
    $a3="{MD5}j7tl1TQKPambSdpKWE9CvQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}