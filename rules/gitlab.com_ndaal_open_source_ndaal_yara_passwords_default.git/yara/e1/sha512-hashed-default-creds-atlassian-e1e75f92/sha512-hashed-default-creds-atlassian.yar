rule sha512_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="9ec66837c9fdc1508e24acaa41d148e22e03bd473fc5afd11d230c587c766be13c8f865522bc6bf3e0eaf927c97b6dad80594881bedaf1c06542b55842f45698"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="4cfbff66f656e328b2b7c593bc198174b1e09b113816040c8f567cc26f03c6abe13ef411f6f5e4c99d7928c23e45ffcb5714aca00bfbc626c8d31ce068dfa8fc"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="2422209232976a5ab86c86ebe89e63638ecce4c6eb6fc09896e5528b08c89f9db46cabc46f352c12faeb6e08afdeab43b5924f111c5c375211696d267d4fb980"
    $a6="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a7="36f0d36e6f020fc648af15606ecda7c25fc78db989fbd0eb5948504b389f92aaa3c3b934b2ae18f1104490a033f732efbb03526938ded59e944be89e0e9c6bc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}