rule sha256_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="636485868971eac5aca33c4a0e1800a8a11d980bcf0e3776b31002e2c5db91b2"
    $a3="636485868971eac5aca33c4a0e1800a8a11d980bcf0e3776b31002e2c5db91b2"
    $a4="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a5="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a6="f131554f0d1f881882e0fd220e72493303b24f48c9ddcf6677021a22048c47bd"
    $a7="8c53ee5f5550d1780fa9b188312e51356c2557ec2b42e6ff4629065ad122d959"
    $a8="d30a5f57532a603697ccbb51558fa02ccadd74a0c499fcf9d45b33863ee1582f"
    $a9="8331934c92485666371bf055722c9474f157976d06cd300717481aadecbb29a9"
    $a10="67bbf4879bdefd3e22c2362623daa005ccd10d17e037e0a3d3c09484b4f03561"
    $a11="67bbf4879bdefd3e22c2362623daa005ccd10d17e037e0a3d3c09484b4f03561"
    $a12="25aa32e90623306ad05845b68d15e6f6c58432213dae7abfa7fd5dc04c7eabb1"
    $a13="25aa32e90623306ad05845b68d15e6f6c58432213dae7abfa7fd5dc04c7eabb1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}