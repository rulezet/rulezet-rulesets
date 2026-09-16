rule sha3_224_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa02dd09bb553f7f6dafe5d63376e2a9ba6f6456d771dba3d579395c"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="2ed423e5a917ce63762d33b5abc0fedf6fe1865cf3757f90dd8d9c91"
    $a3="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a4="d517284bc62a9f2e1b07294dc3ba59bf99a02382967dc25d8764edf6"
    $a5="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}