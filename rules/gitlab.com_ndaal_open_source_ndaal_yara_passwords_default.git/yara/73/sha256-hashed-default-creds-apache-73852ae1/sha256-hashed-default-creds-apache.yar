rule sha256_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56c38f358879bb1795ed9207167936d94710eee6d6380798ec62c9d10e40ec01"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a7="4b168d88dc872a7753c2bc35b36a2d4249487af55baf78f247f38cae2fe962da"
    $a8="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a9="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a10="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a11="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a12="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="62f196fe59c6f78d7f332ae80f55e6e869d8e7fbc589855b5a1a21b9249408ca"
    $a15="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a16="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a17="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a18="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a19="ff7772053abf7d817d6eec229a09e14f0d1552f1cb0aeedb2ac73784ac2d2e39"
    $a20="51b912f34ae18b4e5ad349f50bc6fdd8d9a605d09bab4f302a09c7f790854296"
    $a21="07ffa23817eb0c999f8e126a39db481e61fe4cd14a47b700ddf8c9b31718f912"
    $a22="51352afa310882a95a923680d65d44fd33fb1468849914882b474273ddf506c9"
    $a23="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}