rule sha512_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2c1b52dfb944b670a3c9fbb748bbf981700f06e6dbc935d407783fd44fefec23abb9114030ab40a3121135863b99ccdd2e1db858c3ad5c8d9830d231f8645095"
    $a1="772803acbf87e50abf9d8048151cfac152bb61bd05ce50cb3ff4a5c5e0cf3d256915984afdbbbfb42b69b8762a6fd55fff864484c212534aa8e694eb90c4c631"
condition:
    ($a0 and $a1)
}