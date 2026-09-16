rule sha3_256_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a4="756a2f17b28ae108e6239416736a5471735481b366ca9eda3caf9ae382a5e682"
    $a5="756a2f17b28ae108e6239416736a5471735481b366ca9eda3caf9ae382a5e682"
    $a6="6aea42640fb12d8ba340110ed1ae8616cbb08cf0d5bf4aab3a28a47089f6ff8f"
    $a7="753018e757e13828f825cd2ad313ab06a567ab60babae2725c5c8951a95e65f6"
    $a8="d7018b6fa16cb915bc0383ffebb50f8e49cd9ea4ff0e99801edbc6c0932beaf4"
    $a9="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a10="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a11="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a12="fb2a49185ff85e19b80a5046bca671f1c2f39a41eb2b94de092724f5e90d7a40"
    $a13="fb2a49185ff85e19b80a5046bca671f1c2f39a41eb2b94de092724f5e90d7a40"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}