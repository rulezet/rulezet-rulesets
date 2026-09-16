rule sha384_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e71efaf23c5c76bd9286b89306a8226d8f77fd7a17299fe56f2a36ce2cd505b6eb314dd95a5d63ffe0b7cdbb7e86895c"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="e5725eee11d0f07ffa8f8dfe5e4305bf127f714555fd515835b6d74f06aef91a0ea5866d6fbc7c025266c41578f26443"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="3ffe983f04b0d7364baf4bf7633a38e4c0dade270aab3f883383156afb6e45104b56ce8c7228efa96ce04a3ab2ea675f"
    $a9="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a10="1b52b016bf98b7e67fe0cd4cebfb2d087036ac185c0611af3fcedc59ab80d3f7fc4aba658f900b7ddba64e81e40fa7bb"
    $a11="8c438a0b26136df1d7894c56ba13524949c91aa81a5ace7416743392b5ff09ce0f736ff2bb9489f6dbc4d7d834038edd"
    $a12="7714158131b38105ba1a1dd1e427a56d57119056fc672b1d28e79e452ad4456a037b69f8fc8ea09b8f84b0361c403ac1"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="54dc0bc33ce667b5fa8052d34f340e4e843909703025cdfa71b69be58dd495d519314e825bce845c521219b37a396249"
    $a15="18cbfb902f16c781142cbe9c134e2b1ea7eded6c1a881678b6f1c5254b719540665f8ec465fd2f1995bafe794ba7d801"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}