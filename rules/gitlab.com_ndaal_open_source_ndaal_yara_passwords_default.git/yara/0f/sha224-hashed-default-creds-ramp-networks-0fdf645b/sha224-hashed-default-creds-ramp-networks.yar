rule sha224_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68a2abc62150102cd4275706bbfeb64fb61ff0fb35e934791ecedf20"
    $a1="9ee1fc2d590a7ddffc1f0f7c2d1c4e77e07715243f38f9c0b317b810"
condition:
    ($a0 and $a1)
}