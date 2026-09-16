rule sha384_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9c814a170b0bdb551e56977d25d4c41150dd02da15089fd514ba4a58761bc49c02c91808f9a009a4660e456f1b103f2"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9eeb6518b1a04f055c79e4deee94ad7bdb24eefc068f836961f3b98bfcac51ff1af93af6d86fa2d115f14b13c241974f"
    $a3="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a4="8ea2e856001afab1ecf0c5afe051f10d1280709567e24ac0f156a58294d6bfd6b549077f6f89ced812ea04cdfce0c578"
    $a5="233a0c3b653358b1b07cf093e7b2e36a54bf4c66d5736db17ed145b18520c9108bbd9ed53bc74de041e15f1476013b10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}