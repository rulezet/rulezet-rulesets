rule sha3_224_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c98463652e78dc9aed2411abb079c3ccaf5be3ca000e3cd4683e2de"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="7f78bde7d00ad633633eb5cc22118e11d93e96cfb22887abd27f25e6"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="40377f8ab627ae88a37da8ded5993ff24129bf3e824c803a57c04f14"
    $a9="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a10="aa1f92728d09b520296e2969685797efa62ce7a9e03283b641c78ffd"
    $a11="e588e772284639c0b704b3a3579c75048f588e26d7391642e58db5a4"
    $a12="def96bd6cde0d3bfe76786dfd9a2568d168335ef8223c8c74833c98e"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="3d0f2bee930d492e3c2ee402175031cd4539f554522c424dc86d31f9"
    $a15="09620fd7325bcd5af39bdbfbd56a57991823aa514e84f19eb5c23c12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}