rule sha384_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e59dc20e2eeb258a8347a590a2e40be973fc018899a47190925c5dd88bab783e8017d201e4f8fb3dffc8489c81787b7d"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a7="b4a85c5c35a16d6e36c16b21834b1b21c68a263499fc3092ff27c1ca1a2a5c88d0344b31130a03b8b74317754cf2d9aa"
    $a8="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a9="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a10="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a11="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a12="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="06398a1556e8b7890d09872506ba5bd4f262cb8f21b244f792d5511e4e9d73e8e7de8ceef7fa497b730b0d7a4b24c3d1"
    $a15="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a16="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a17="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a18="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a19="6f9e97f59673406a33ebfe62c041d77c782ffc3187b90d0d7d9523be81e2430250d2753eb2d6bdf94e0a96414ee0d76e"
    $a20="8844314f91950ac7ef0d2dd510edf08ee2ee760c8ff0baff3b61fde2b49155ad65e9ac2ffe3a1f1879b53ba6336ad8e6"
    $a21="a490369260a3a7c150bb597583110c7f0c8c99812ea4ca73760920b8ff18a7c3f9943d3c3203cc13cea0a19fc222d0e6"
    $a22="c849e711ad8b1bed6e23bb4cac212e4bd8b4ff3a9a3fbcece8525b783e3cc0821c2011ac8cd939a27a098480a28aef14"
    $a23="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}