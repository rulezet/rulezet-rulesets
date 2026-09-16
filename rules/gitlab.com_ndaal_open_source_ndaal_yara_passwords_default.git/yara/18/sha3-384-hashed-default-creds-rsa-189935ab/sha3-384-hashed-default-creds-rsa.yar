rule sha3_384_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e435bc01e97a55221c5077fdc20035a50d0df4c496c2a2366be9be382b5307499b17ead047b3d49c2622cc0fbac9679"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="a9d6dff71f0b196db07620445af4141f5a622dbfc7a2b81ac14f2bca505e7a7966cd04e4b1f822775f945063b3f7eaba"
    $a3="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a4="8b70e863e504e52c07cd07d5996de3bb6c1d04c9d1121543271b89354c594e1f931c27ab8ba1d48ebe20541ccb515b97"
    $a5="06ff6516b10e34580acbb5f2b05ae2628cc1c661fbb3e50b31dac0d0fc5be94784163e820aed296a54555a0d4ecd0190"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}