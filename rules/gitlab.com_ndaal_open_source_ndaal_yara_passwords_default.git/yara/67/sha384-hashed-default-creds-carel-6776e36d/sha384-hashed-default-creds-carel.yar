rule sha384_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4ef61652a805fb93c589ab76b6b69e5edc5f8253555fd287334e2c70bfc1ae843a77ed357f957e361a0dbd10975671e"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="8254f988ad2d54011453d89d1b599a1df82ea03fc64d0f7d28727815e4f12df5e81737b9492192ede1e16f5ef4bc41d3"
    $a3="b2394f271560fd38c43a015c1bd2ebf6ef5c16220d4ec912495f3bd606e352cb2c001148a7af463c261e2f24168d5eac"
    $a4="9955e839189f954aa7ef059a8cda487c82e35fb96284b95f6ccd4f049a4ffa264914633a44a3b96da78c5adfc3a39534"
    $a5="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a6="aa5ddc5015acd038dd0741e0bc3768d5842000425f47810c9d0c9c495d8ed939677f7a7ebcda2628758be13718211f90"
    $a7="8bf406a777126d0f53e43c230b9d55746ac1ff5e5b8cd5090a9ce1aa9bbaa508cb9046bb5afb23ca4742d476b8b98dac"
    $a8="0de7c99fc9145cb5c8385f3df2483785778a210d2f466af9ce811c46f9699823095b7f9f0d19d9383a6d054ad60be1ab"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="8cbfd7785b1b9ec76a26eb24aaaa09110b59edc72449319e3636e0f705dd6238fddf06fefcef3052b07b62ea67f86662"
    $a13="abf96f2ed771d9f7d6de913e112d31c7cfc58c8b30643149bb88efef03b94e3a5ced8c13bd4840f4c02795669e1e0fab"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}