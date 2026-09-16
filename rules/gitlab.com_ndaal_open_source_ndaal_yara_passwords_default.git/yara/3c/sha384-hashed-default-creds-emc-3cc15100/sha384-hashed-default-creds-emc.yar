rule sha384_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="5ee1d08abec5d818b59b0e22d5ded61a05e835fe9ea8f68ca9d0210800e3b4adfbd56ca4648c918a6e4ef74b1e3ecb91"
    $a3="189026f3f234f462081bec6ca8aec82b2d0405369836e45e358555d61cccfe4dd35d39a85e67d06fd9239bd29826d6b4"
    $a4="abfcd51107009802bf80ef9890046f35ceb0b0e0025ed356201caab7ec8737cb5ac2f34c2be25810dcb72bfce15caec2"
    $a5="997d685c0ab93f3714463271d73b5f7064a6ec43806615adf6e9bd8e1a4abd2cef990dd60f135410468fa5571580db0d"
    $a6="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a7="7a9cac3d082c3375ebf63ef9de32c142fe23117a1a23eb5b24037d3da85db7de7d21176bef4e63d0b78f325e0ad17533"
    $a8="a18e313ce6550be03c864a81eb16c38b507e2c4142bfa2eb4c3b25053614ce1da4e435d7cc610f78dc62feb4701738e6"
    $a9="56b4f1b14027ef9b7d102a99a9f5d68b6b6a69f7d7fe89c97f9ca2aa524304ae96f929ffe66ffd6bfb18ad82842d5143"
    $a10="a008bea21ec79efe3e8d690a1156d8361e38f5b99b85dd26084c1a94640f8448c56e3848fa5ee3f07aba440ab9b2454e"
    $a11="b3bc118b96622f2a6cc6f1690877a834694522f799f4bc14c1e624f40bc9a5cac5c8a9daa5cf982a1512ab9d93e61ae6"
    $a12="b2aca9aaeed84dfe91c250a4ca19e03c631fd868b6306e7eb9b28f54ae621dca34bce15c6c104d3e41f56cd2b9f2662b"
    $a13="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a14="7d49d02c105312b2b69de69141b27de1f4f4c202b4afb19d7ff7ab9849e9ce2da165a87eeec971bca66c8eb8a9243f5e"
    $a15="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a16="366176015e92031d29279a1931fff636af422057ba28f8bd90fc5ac06c377659fb2266bf9e1e3028f3d76e0a5152bf43"
    $a17="773531f1235a3c4213d2362fcc216b29924bc178d7636e5a1008ea3103653c812bdd96a6074feffcb86f3928334fef0a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}