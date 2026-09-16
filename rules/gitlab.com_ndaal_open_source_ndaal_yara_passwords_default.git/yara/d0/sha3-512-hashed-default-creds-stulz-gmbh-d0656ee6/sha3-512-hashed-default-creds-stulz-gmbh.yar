rule sha3_512_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30eccf3155cd5f61b81e7de30056cdb5d5d802c6d7f5f29e8a67d9366fc6d1d2cab994e0deb0f5e3380036affb6154c2ff55f8a85dc032bb5fec03a56c657072"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="f1ae060064407f6bb998db494caec1a7c7a66b24569eccabb9f41885d0598f3be57bf9093fc598337a50c214ce9887b8fbf32309d3878cfc0f5b89b0c89886fe"
    $a3="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a4="aa41c7dafbab8c80220e28d57aadc60dfbdb398f5662a69a23e609f2589c4b1e6919e2a0b2b9cca7741d2080243227c2fba8e052df81ea8d1011a27407600b16"
    $a5="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}