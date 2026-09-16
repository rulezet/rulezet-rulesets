rule sha256_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a612393342c59ffbfa75d39d4d835b8a9c4c7304f905c8e7c4f0daa3370b9a39"
    $a1="a854f223272439fb3283b59b6b8b2fe2af9bb8928195f8e95c6df1f1d3fb108e"
    $a2="36de721b186948b4b4cb57646821ab92bf1f3761e6a20c60aa9e4f95c745b411"
    $a3="36de721b186948b4b4cb57646821ab92bf1f3761e6a20c60aa9e4f95c745b411"
    $a4="a6d59b0e8887006a67705e4f3dca1d17255189d72246bcc02029cae88b8a1390"
    $a5="a6d59b0e8887006a67705e4f3dca1d17255189d72246bcc02029cae88b8a1390"
    $a6="e77acd8538f6e047e5554aa775c5b5faed636ee6756c4fa341003d7d4b79aa2e"
    $a7="e77acd8538f6e047e5554aa775c5b5faed636ee6756c4fa341003d7d4b79aa2e"
    $a8="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a9="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a10="48ad05c64445e697d835d27d4e1bd117a87f014ba24d972d5cb1e9f6b1cfcfa8"
    $a11="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a12="dd44197298d027962fec302ec92f19666172d40fd73be7070cdc6b9a1f875c0d"
    $a13="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
    $a14="95312f267f428a3a5e31cc6608919a91e72fc046b54b84f81fc0c5276b3490ed"
    $a15="ad1547f6111faa05d0a7adc7d847be23ba631bf7672d671cf5be40af15001c26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}