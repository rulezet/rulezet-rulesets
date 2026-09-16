rule sha3_384_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fbea380be13719486a2bf0e03a60152bc75d89e7c3e9ac25397af9cdb54fd75294ace3b5402452f1e6a02070c71dd2f7"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a7="ac99676e05cf6a08437d21843ea0824dbe23e8a1e399b04bbb21d4a2ca04f3bcc1eb70356f8251702c4cb75ce74b732a"
    $a8="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a9="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a10="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a11="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a12="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="435f09fa12c71aac27c792a47a224b24f5affe8b99b3b183e26bbea0802179e9b7c96c24aa2fd9fd93d359a2f801fb87"
    $a15="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a16="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a17="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a18="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a19="a1f5255687bf673ce2b0274732b948132c9e2795ace12b986c5ca721bc80c4283ba6edf00b620c887abe4220d5d57def"
    $a20="09d437fba875a597a6d2a4715c2a5650fe66611c10a306e12453cb7343ff02e1a30b1cba523a6deae1f252ae2f60cb55"
    $a21="2e3919ec48ad5159368a56e09764a055dffd3371d8b1505058d2870fd6254f22c85ef6fa2d02084b6b74db20e74ace4b"
    $a22="60b3eef0d556ad8db1b1911e337527ae834b29f518a447088c72c4bcc515892f7b1e01a3746b0eb091fa78f797007bab"
    $a23="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}