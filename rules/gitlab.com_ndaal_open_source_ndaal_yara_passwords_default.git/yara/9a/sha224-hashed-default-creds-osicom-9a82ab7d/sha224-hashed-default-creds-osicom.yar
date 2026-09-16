rule sha224_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a1="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a2="88796e3e59767d3ff43367b26f6bf9ebc13168d3ef032b7a674de5f6"
    $a3="5cd7fd4c793de52376f74a016cf373db2426deac143682521f0d7779"
    $a4="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a5="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a6="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a7="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a8="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a9="88796e3e59767d3ff43367b26f6bf9ebc13168d3ef032b7a674de5f6"
    $a10="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a11="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a12="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a13="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a14="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a15="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a16="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a17="ce33aa88b282b5decc0494567889ee6c5bc69671c5b1884ca0b93cc3"
    $a18="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a19="7c3c192db3e2318612c10cc63392760a6ad4b0e7ddf757858e96790f"
    $a20="b08b1001678f48f23d2cd765b8e5b804033053f5468b85558317d49b"
    $a21="06b6ac2318e181873e4283a77412e1592da0db2c108eab9c3baf670b"
    $a22="2a12e8d906468d24de4552c04fac544c36a2775d6a4d206bbf20bb43"
    $a23="d951a81aca79223a7f557f032ea0d8f773f9867b74004a4f3125c23b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}