rule sha3_224_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f90f2c99d36972d59353b28fb98154d2619b681dbc481a1fc88616c6"
    $a1="09dce0ca05c368202e5478365e75ab15c529903416808e8a61bbb542"
    $a2="9de87879c673cac94dc6828ec80ce39914fd4680a986391aa5559885"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a7="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a8="bc9c2a8b440f42b11a6a557208153c5435d994fd4ad4dd45cb70a773"
    $a9="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a10="cc2b9547d268c03f7f3ced4129df0c2322618d815753e62aff3e838f"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="e6cc960a467d958a458008e3b63832a450d6e83f8dc213d7fe088450"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}