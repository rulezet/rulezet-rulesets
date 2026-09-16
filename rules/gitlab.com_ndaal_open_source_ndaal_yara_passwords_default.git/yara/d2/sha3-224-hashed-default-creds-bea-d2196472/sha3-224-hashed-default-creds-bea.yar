rule sha3_224_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="c19957d1594ed5e0474847c416fb91e9dc8ad3668e25fcc3971a3537"
    $a2="64a5f4e4de37bf608e98ea275502ca5a18e4438280cab8467e59b98f"
    $a3="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a4="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a5="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}