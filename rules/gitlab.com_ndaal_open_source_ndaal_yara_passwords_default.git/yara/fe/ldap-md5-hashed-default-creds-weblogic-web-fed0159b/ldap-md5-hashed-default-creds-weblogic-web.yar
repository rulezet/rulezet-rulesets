rule ldap_md5_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}5r3ioBxJDhd9bc0VwUnBKQ=="
    $a1="{MD5}5r3ioBxJDhd9bc0VwUnBKQ=="
    $a2="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a3="{MD5}CLVBH4SKJYGkFnKnWchzgA=="
    $a4="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a5="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a6="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
    $a7="{MD5}S1gzdrJ2e5I8Ph2mDRDeWQ=="
    $a8="{MD5}zQxgktamh083n+SCftHbiw=="
    $a9="{MD5}zQxgktamh083n+SCftHbiw=="
    $a10="{MD5}HQJYwkQKjRnnFikrIx4xkA=="
    $a11="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a12="{MD5}1B6Y0er6bWAR06cPGluS8A=="
    $a13="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a14="{MD5}X03MO1qnZdYdgyfeuILPmQ=="
    $a15="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a16="{MD5}RDJ2gd2Sat3Cp0IlImIg9w=="
    $a17="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
    $a18="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
    $a19="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
    $a20="{MD5}S8P7JS7fjk8SrPhcCvYzzw=="
    $a21="{MD5}S8P7JS7fjk8SrPhcCvYzzw=="
    $a22="{MD5}ZMWxK3cp5Qduqld0NgQpUQ=="
    $a23="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
    $a24="{MD5}RDJ2gd2Sat3Cp0IlImIg9w=="
    $a25="{MD5}SpY3Tmzt1eqIw0CaMXowTg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}