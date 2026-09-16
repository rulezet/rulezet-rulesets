rule sha3_224_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e09698e1aedfb454e0009610f341a60d3e09e679ad39adf9aa279c9"
    $a1="2e09698e1aedfb454e0009610f341a60d3e09e679ad39adf9aa279c9"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a6="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a7="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a8="92198a905f60a0f01036be1fe87616773251701ad160d0d397b5c813"
    $a9="92198a905f60a0f01036be1fe87616773251701ad160d0d397b5c813"
    $a10="a3920304e1b144139c410c1cbbf79f14fd4ad5fd3d2cbedba983ef81"
    $a11="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a12="7407d101c6ec8cab3ece152481870447479a1d165f3ff0ee42872050"
    $a13="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a14="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a15="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a16="eb2eaaf9ee70988807168afebf88c1448c2a51859ddf7d1747c08df4"
    $a17="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a18="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a19="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a20="26d99ddc43ca52688cbf0ec95bad21a6d0f44a9e6e3f633d64955e42"
    $a21="26d99ddc43ca52688cbf0ec95bad21a6d0f44a9e6e3f633d64955e42"
    $a22="5afecfeac04ee939ab7df76c8619bb20d8400280820a6a8d71189f94"
    $a23="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
    $a24="eb2eaaf9ee70988807168afebf88c1448c2a51859ddf7d1747c08df4"
    $a25="d2d44554acead1541ae4dcd07e2b189e4752e13c255c450ff9cb1ff7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}