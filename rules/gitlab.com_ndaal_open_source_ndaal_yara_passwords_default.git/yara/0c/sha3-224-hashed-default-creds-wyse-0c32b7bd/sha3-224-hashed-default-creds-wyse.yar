rule sha3_224_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="def96bd6cde0d3bfe76786dfd9a2568d168335ef8223c8c74833c98e"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="3d0f2bee930d492e3c2ee402175031cd4539f554522c424dc86d31f9"
    $a3="09620fd7325bcd5af39bdbfbd56a57991823aa514e84f19eb5c23c12"
    $a4="aa1f92728d09b520296e2969685797efa62ce7a9e03283b641c78ffd"
    $a5="e588e772284639c0b704b3a3579c75048f588e26d7391642e58db5a4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}