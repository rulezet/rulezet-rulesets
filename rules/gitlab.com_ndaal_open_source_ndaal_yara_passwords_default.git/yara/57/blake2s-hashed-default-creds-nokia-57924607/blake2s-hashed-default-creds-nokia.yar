rule blake2s_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80c86cf3a5c01a69b8a7ff71e0494169e29091fbdcc74deb27b0424b063da631"
    $a1="80c86cf3a5c01a69b8a7ff71e0494169e29091fbdcc74deb27b0424b063da631"
    $a2="fec1c25022e096836f4a607ce3f6c200abea8775cbb8bf8a7ca78dbd867c0e0c"
    $a3="fec1c25022e096836f4a607ce3f6c200abea8775cbb8bf8a7ca78dbd867c0e0c"
    $a4="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a5="ff95b804efe8412a293bdff3bfe9bffa0251ea7327f243a195bc6e1f68f16142"
    $a6="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a7="47677dd17a17a8bc5b12a38ebc591c4dbb68499e929807a83244e372f639a32a"
    $a8="27ca50c9efe17c2d0871a3a5b07058eee51e0fec449450a463badc34be9cfb72"
    $a9="47677dd17a17a8bc5b12a38ebc591c4dbb68499e929807a83244e372f639a32a"
    $a10="309d4021807c32d3135c512b63aa35eaa712ecd016557c758650e38444b54f1b"
    $a11="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a12="c7867568fc4b7b2650b83f24a57e6d028f3c40e2b232f5ccbe8e1e99544a3833"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a15="94a80f8591a0d6bdfa8cc2126602a3852d92708079bad3ca3a814619898e7067"
    $a16="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
    $a17="cf4f5c761da7a1c4166595e3b77976fe3135e6de6adea29f47c863bc4cfeef32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}