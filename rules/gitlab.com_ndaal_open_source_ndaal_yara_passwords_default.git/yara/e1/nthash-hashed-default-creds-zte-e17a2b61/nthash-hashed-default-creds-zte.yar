rule nthash_hashed_default_creds_zte
{
    meta:
        id = "6i0AkU0xrmxF4FsmW9G1Ie"
        fingerprint = "447525771e2460d94663ce63ecf47262922793cf84347fd8f6b5d52d972178b4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="178b064527342016b963177ee399f71c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8cec5308d16b7b319c395f74988dde17"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="57d583aa46d571502aad4bb7aea09c70"
    $a5="57d583aa46d571502aad4bb7aea09c70"
    $a6="011c7e804b2a3e5be12eaa63478e5ada"
    $a7="f9b38088c195c15e3cf9fbeecebf14f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}