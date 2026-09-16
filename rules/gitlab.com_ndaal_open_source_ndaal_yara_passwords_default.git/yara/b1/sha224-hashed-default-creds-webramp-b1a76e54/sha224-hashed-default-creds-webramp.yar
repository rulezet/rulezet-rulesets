rule sha224_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b1d1b3fdf9951558aa01171983af4e2911f703ebca3d489c6dad0f4e"
    $a1="9ee1fc2d590a7ddffc1f0f7c2d1c4e77e07715243f38f9c0b317b810"
    $a2="68a2abc62150102cd4275706bbfeb64fb61ff0fb35e934791ecedf20"
    $a3="9ee1fc2d590a7ddffc1f0f7c2d1c4e77e07715243f38f9c0b317b810"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}