rule sha3_512_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab278665a311f812d0ebbb92f95de813cc87efab66f24e6fbfcb9e2a91b651811969b6604c9810be104adfa7de46491653af20d15e69b77d62310ca2569e4635"
    $a1="67dbd1aeabd7e13817abee6bda3460715d1dd15e6a52098496617cf554f29ba4103dc675088c430a915a9f858dd0391834dc8b6122a100279c599f609905eeba"
    $a2="4e84f4ef7dad9f772ff78413fea586c65c972918ecbd3df4f183749a850d160ecffdc1199001a3df901f1191b377bb9db7bb2f81206f572c38d3f3c4fa82553d"
    $a3="a7edafd8ef3c6d2238af6e6dd12c7ce7d88f6e4e8497a89675bd0e66e11d82e802f0b7f72d170c75168cd91c18cf8ac738187562b43234016cd1a2962f85e6ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}