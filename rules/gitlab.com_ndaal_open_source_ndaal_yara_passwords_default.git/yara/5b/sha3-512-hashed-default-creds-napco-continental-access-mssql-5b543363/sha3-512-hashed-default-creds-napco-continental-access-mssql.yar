rule sha3_512_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a1="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a2="deb019673e9b858eefe959067862d59d390101f67cd4fa7c4ead9dd66e39592d8ca578220fbd0a6d430491565a94a011f54847154fa69286c51694b8f6bdea6f"
    $a3="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a4="c83535b5dc2c468944618a2ae54fe4f522b45728e387f198d042b3bf28c03b0588b1cb39cad3c3f0c31b09ad7a8925470acb63ab1f24c1f71ccfa270e86f43b2"
    $a5="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a6="69d9d38774579a3bd7621666014e9d701ccff419e6247a5a99f878c79d14d5eaec425a10d11115cc6e98a987a8f5a6297af6f1d261cbd31722b1ef02ec98ab7d"
    $a7="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a8="deb019673e9b858eefe959067862d59d390101f67cd4fa7c4ead9dd66e39592d8ca578220fbd0a6d430491565a94a011f54847154fa69286c51694b8f6bdea6f"
    $a9="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a10="c83535b5dc2c468944618a2ae54fe4f522b45728e387f198d042b3bf28c03b0588b1cb39cad3c3f0c31b09ad7a8925470acb63ab1f24c1f71ccfa270e86f43b2"
    $a11="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}