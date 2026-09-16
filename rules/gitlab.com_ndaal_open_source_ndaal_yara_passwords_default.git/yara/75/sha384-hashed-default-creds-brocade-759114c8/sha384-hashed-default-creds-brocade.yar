rule sha384_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102e13d0ec054aafc760a18e5b91637b4ae9706e40e64c4a1b1bd98b1b1bdcc14a48c8410d22f264367b41575f7c1cb3"
    $a1="a35e580c5e221b1031137ad24f272e05cceb72d5f7f6821320e7ba0a883154491948600073e063ef9d89a91887775aa2"
    $a2="0a3d955645752ddf0caa5651b8003c646948f054b99f54d8f107615145d34e798094da981d057814a5c841b6163af0ca"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a7="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a8="46776ca3f232df01dc5bb25abb9ca0e63e1f2253e38ae2d3b07a8389f26e8db0fa526faebb9d7c9d920e13a9f788559c"
    $a9="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a10="166bf8db77282ff4163af685cc2c36fccff42d2af7d83dfa0edbb900a87c3685b8c77fcf3320ed608e51a9e42f6a2e2f"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="2e4e826575449d44d6ff35573dc6567d87b3e9eae808ddab07ec439c23d54558955a9dc5c720a010e7292681a002066b"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}