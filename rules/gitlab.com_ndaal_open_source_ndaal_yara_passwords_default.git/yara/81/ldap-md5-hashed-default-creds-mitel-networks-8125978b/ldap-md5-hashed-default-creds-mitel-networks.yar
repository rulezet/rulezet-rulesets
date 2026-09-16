rule ldap_md5_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}zkmkUTqvAhWx7ci+3jmMbw=="
    $a1="{MD5}EJ11tl2oQAwvNGWh9f7tHQ=="
    $a2="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a3="{MD5}lzhCYbi7+WbfFuWtUJki2w=="
    $a4="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a5="{MD5}Osi4xLaFVuUhkiBS+LBJtA=="
    $a6="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a7="{MD5}Eohrp3H/Jn1PIbCPquD+aQ=="
    $a8="{MD5}zkmkUTqvAhWx7ci+3jmMbw=="
    $a9="{MD5}rbB0zzkZHW8LIh4iGM4vSw=="
    $a10="{MD5}7NesoseWc9JEGHNcm1ZwLg=="
    $a11="{MD5}VLUwclQO7rj46TQ+cfKBdg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}