rule blake2b_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="10d64a40345dd323b7018e4613879a2820082dbd988d97a3f99a86c798ca65bb0d467c65a460965922dbd7a2355d07d3b2bdea1bea7b2db93c64e1c96d77d366"
    $a3="10d64a40345dd323b7018e4613879a2820082dbd988d97a3f99a86c798ca65bb0d467c65a460965922dbd7a2355d07d3b2bdea1bea7b2db93c64e1c96d77d366"
    $a4="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a5="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a6="d0abdedf85b83b683640038be19525a4ba78d34398117a357d9098430fe43a052aa9e4d80b3f17934052b61e227c8f434dcb00c47fcf5524d583172d8964514d"
    $a7="3301bd06d3485af0a0df4bfcd1ab65da77d62778fd062308d914378829b51f9af4d6a34d4e040ad435e543d6adf7c3f458baf920f1ef22b72d6134985b8bd89a"
    $a8="cf4b2774a5edc903d52d8882676571f62ea4057baffebf387a2d561d7f29cf4978b7b2448c625455d901e726279fb7e033d5769f50488a5cd0978f99b6d8ea31"
    $a9="7225ad998b13bc884bf5b5aa75d5841d8942c84981baf5f822b192b7b51b69cbff817a2fe9d32ce839254c580e54dfe25240fd12e4ec02a91a54ddad9ef5de70"
    $a10="4cfd51b33aeb5a046c71a3f315cc5b84d20ea1066e92e9f3ec5fc8db10068ef43268543ea13606e230675db965e44bd878867c1b322856a0001bbc7f6545aead"
    $a11="4cfd51b33aeb5a046c71a3f315cc5b84d20ea1066e92e9f3ec5fc8db10068ef43268543ea13606e230675db965e44bd878867c1b322856a0001bbc7f6545aead"
    $a12="3f829f7c771728a8ffaea8e41ee440282b5376b001c3dfe7b73eef7b2fe8cd033c953dc66b74462d40f8623b8a1b15fdb875b1ae7c97d00bc5d22c8c2fa65c5b"
    $a13="3f829f7c771728a8ffaea8e41ee440282b5376b001c3dfe7b73eef7b2fe8cd033c953dc66b74462d40f8623b8a1b15fdb875b1ae7c97d00bc5d22c8c2fa65c5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}