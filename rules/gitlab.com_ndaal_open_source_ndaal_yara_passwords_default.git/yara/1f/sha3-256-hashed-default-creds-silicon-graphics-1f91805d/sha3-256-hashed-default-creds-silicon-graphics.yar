rule sha3_256_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a1="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a2="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a3="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a4="5797a2d496895ea43837aea62626527461192f68d69c93c42afcfa8584942bd3"
    $a5="5797a2d496895ea43837aea62626527461192f68d69c93c42afcfa8584942bd3"
    $a6="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
    $a7="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}