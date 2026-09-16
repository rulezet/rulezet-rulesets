rule sha3_224_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a1="17b113d0e0afe1192c18bd1d612632793d346184c7daf31bf98f9af0"
    $a2="55c9a58ca4eb087e81629c41e4eff494ee391919138d7f26530dc03c"
    $a3="55c9a58ca4eb087e81629c41e4eff494ee391919138d7f26530dc03c"
    $a4="319ab48e6fdd5134a5381dbe1d85ae88df203f87993aab3708cfdf28"
    $a5="319ab48e6fdd5134a5381dbe1d85ae88df203f87993aab3708cfdf28"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="47074cf4234a97b93f1df3b473877a1485bde791a82dd441684bd8fa"
    $a9="7f1727d8c6a704406c8e4e1de7d4d19b339a8612ecb67342ba65a571"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}