rule sha256_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="e82fa6befc9aa14d0e2a00c3a203ae9dfeb3dab2a11129f48be1e08264c4ae77"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="1e40a275a84b46f5603c7af871598c5a56bd51197a81a569ca0cc03022b8c303"
    $a9="35cb3600ddd4ffa04f69f0d63033957934464a78f532bafe60dd9b8e83437949"
    $a10="efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="4fa360a1ddf2a68eab861d8e866e3c5cf5f9b4189c91bba1b7a12f09e5dc2a56"
    $a13="4fa360a1ddf2a68eab861d8e866e3c5cf5f9b4189c91bba1b7a12f09e5dc2a56"
    $a14="6b3889171631e664046782e8edc458d9d47712fcf19f5b070b374c27926bec09"
    $a15="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a16="1c139a022e0fa9e9a67d4a548a6217b49fc55c2e706f67a357fa9678fa4a77b8"
    $a17="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a18="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a19="16e4f26d3662eff5d75341bc31a5457d54d9a720186ae17bd3f7dbdee91e2943"
    $a20="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a21="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}