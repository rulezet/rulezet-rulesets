rule sha3_384_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be4e5ac1fa95b582138a63f719c4dc273285062ec176c782d1389fcecb927ae23f84d3b9c1a2f97147586f4a14e6fb82"
    $a1="f103f060a02ed478413a913832032639cb053f49004e7748f86209dec765590eb18b8283615c5b327acad1e890cb4dbf"
    $a2="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a3="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a4="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a5="d842720f00c37bb0633fcacd07e3b4ea340537055c403bc7f8f44a8b58c3c7f237c172f190ee43251fa476393b7f7fef"
    $a6="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a7="fe8b92c719a13f843f723df016f92e0a43f05be1a338709ec27e0e414043ebe0027de858a133a7a1091af7fb110264d9"
    $a8="be4e5ac1fa95b582138a63f719c4dc273285062ec176c782d1389fcecb927ae23f84d3b9c1a2f97147586f4a14e6fb82"
    $a9="9ca8d93e37eab663a9ae822e4022b903813271ee59051bd6cff6efbf0aeee1ae8c280197b29a52991e64a0630501360f"
    $a10="08cee9949c412eb0d7cc99e85ce5ca6aa75ba22d3be7ce50b47bcac8c598a52b6a921e6d0effa594509f104858e2e34c"
    $a11="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}