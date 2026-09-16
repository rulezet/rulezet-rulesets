rule sha384_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7714158131b38105ba1a1dd1e427a56d57119056fc672b1d28e79e452ad4456a037b69f8fc8ea09b8f84b0361c403ac1"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="54dc0bc33ce667b5fa8052d34f340e4e843909703025cdfa71b69be58dd495d519314e825bce845c521219b37a396249"
    $a3="18cbfb902f16c781142cbe9c134e2b1ea7eded6c1a881678b6f1c5254b719540665f8ec465fd2f1995bafe794ba7d801"
    $a4="1b52b016bf98b7e67fe0cd4cebfb2d087036ac185c0611af3fcedc59ab80d3f7fc4aba658f900b7ddba64e81e40fa7bb"
    $a5="8c438a0b26136df1d7894c56ba13524949c91aa81a5ace7416743392b5ff09ce0f736ff2bb9489f6dbc4d7d834038edd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}