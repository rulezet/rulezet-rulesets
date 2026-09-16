rule sha3_256_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="91f679a7fe843734184eb5e5b53a3cb82401336c7750fae790fd6b594619d853"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a7="9f2dc58fe82d1f53a48ef3c0d8b0237125012949b7c159e4d0a78e741840b410"
    $a8="ef10231f890a38ce1fb470f7c566b2fdb713ff364f9253c5b838e73bf8d8c55d"
    $a9="ef10231f890a38ce1fb470f7c566b2fdb713ff364f9253c5b838e73bf8d8c55d"
    $a10="b521ec75f7cab7a2f3aff2631c89a706ff899eb3f81f1457199c73e371272568"
    $a11="b521ec75f7cab7a2f3aff2631c89a706ff899eb3f81f1457199c73e371272568"
    $a12="6673b63f3a87b427a12cdbf510ac140b227d458666f7d6ee2a0dea4526a4dd39"
    $a13="79de1c617efcf3d784ca3b5d1be7fefb1d1287b079fe4527640c36446cd29ea0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}