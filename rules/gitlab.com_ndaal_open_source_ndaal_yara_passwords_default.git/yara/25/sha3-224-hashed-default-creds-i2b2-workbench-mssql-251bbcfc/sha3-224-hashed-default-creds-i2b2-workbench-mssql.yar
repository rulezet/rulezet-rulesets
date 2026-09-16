rule sha3_224_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="669b40f0b1baa7e730091f1fa2080fbc4f741ccbe305c34c38b41122"
    $a1="64beb30422f1ca1ef3e27a39f490a47b1b73765ade570e55b679c4f2"
    $a2="16f30231f278f6831607e260a81a8535def4c876c1f371d8638bc507"
    $a3="ab9776dd3ebf4ff2f26333a785547de0c2bea06780055f82b3e7971d"
    $a4="cbdbfef69d9bb27a9e3c861433f5ed243d1a24ca2980f9e58b1f92f4"
    $a5="5fd28b327a652f086cb914fd1db55dac441969ff0c58497a93fbded6"
    $a6="9fd3c18a4f0dbcdddb971fa334aebef2021e6de71c100ddd1c260953"
    $a7="1573c47e310e794267caf0f2f7a72a388cf3ac2f428d7513c7c29a1e"
    $a8="a1ddd1a85ef1b80b27802cec7ae879c72dd6db2783446366bab78706"
    $a9="2ce74e8b30a6d813fe179a27998730a6b24cd2a9971703a32a0728cf"
    $a10="759a6a8a9eefedef5f97a22f2f11dd85ddb5fa662af55149c71acbf2"
    $a11="3549b6f9b11a6370848279bef528e6136ee56730174ae1ab537b9dce"
    $a12="43a6265a5f1ecaf6d48a8a58c4d382d3a6af4e33cb7177e35d95a1b5"
    $a13="4271fb89cb836139e7d6eb99c30b3339c77b44e0476f45e9d614a6f2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}