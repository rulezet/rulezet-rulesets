rule ldap_md5_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}kutf/uauL+w61xx3dTFXjw=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}DMF1ucDxtqgxw5niaXcmYQ=="
    $a3="{MD5}zC9BADGupAdpkYt623Omlg=="
    $a4="{MD5}kutf/uauL+w61xx3dTFXjw=="
    $a5="{MD5}2Swl1B/Nn4qzVUXvNLHn7Q=="
    $a6="{MD5}gnfgkQ11AZW0SHl2FuCRrQ=="
    $a7="{MD5}YVPgK/Z6obz6NBaNYunaPA=="
    $a8="{MD5}LblejhqSZ7ehGIVWsgE7Mw=="
    $a9="{MD5}bs7DJBtpd6bAFNlhTsf/mw=="
    $a10="{MD5}b49XcVCQ2iYyRTmI2aFQGw=="
    $a11="{MD5}wfF4Kj12nEBITISbh1THBQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}