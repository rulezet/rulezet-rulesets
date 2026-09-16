rule sha3_512_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81b9a4c4774e36ea76916431f85dd466081d6d6049e84047076923ae8e42e3688516f8bca0ba8931e0e8a9a720cd41849e033158c34d272863d9e76cd0b1fdc2"
    $a1="01cd0a94250882dcf22c358fc872c1f54787d3eccbaae6bef60d9ad7b36acfd694c14627580d821a200de77b3fba4842a718aa9f5240500eea430110576e9c73"
    $a2="b38db545289ab9be36b09017edb7fd9a3a3e84036d4dd1b94107d6b90c01b3d43292e853cc7335c709199beae6e23675db7453978d9bf4f3b7fa4fcaae63d769"
    $a3="b38db545289ab9be36b09017edb7fd9a3a3e84036d4dd1b94107d6b90c01b3d43292e853cc7335c709199beae6e23675db7453978d9bf4f3b7fa4fcaae63d769"
    $a4="21982bde5c64a4dd34ed55ee11b99c2e540404656a5b51ce227b6c01cea7cde88a0b2211e325f6e032485593050884eb35224607b19d0afdd0d153b860bd6179"
    $a5="21982bde5c64a4dd34ed55ee11b99c2e540404656a5b51ce227b6c01cea7cde88a0b2211e325f6e032485593050884eb35224607b19d0afdd0d153b860bd6179"
    $a6="bc58eb28bfb4c91544ff73f3d78a304f16afb1c5b6b76e45c6779523e2bdc707f6c94d0ebed502d8b426ea3fa69e222e6e206208d4dc177b928697fbdb0fd33c"
    $a7="bc58eb28bfb4c91544ff73f3d78a304f16afb1c5b6b76e45c6779523e2bdc707f6c94d0ebed502d8b426ea3fa69e222e6e206208d4dc177b928697fbdb0fd33c"
    $a8="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a9="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a10="958aa303d7343f0b4dd0930f3bc34e462049638c80c9f708ae5ba00df74c626505249e671e6b1b2f7f7590a074d96a5589df9b99f0fc71ca615f8ff3fdae9cc5"
    $a11="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a12="127722a6c3fe98b9239edfefbd312abef0e110b453651ae77ffd6145cd5504e7b1ccaa5779e1d950b7494447f81358f63720fd8b2194d1261f3ead6163ba666f"
    $a13="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
    $a14="32cc80d634ebca8d2017ce94e5954d1f8e468e4f3ce2201d0cd246dca0562742edd084744031eec78334be805b95a388da5ef346cd0ebd2ae5dd55c7f05baac0"
    $a15="2448af14589edda190ae6a2c45456beef75ed1187f9de635e26fad843a873f4d9ac74ad4df63d392e039508289ad2b8f5c5ac44be524cd0b422e41718840ee1b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}