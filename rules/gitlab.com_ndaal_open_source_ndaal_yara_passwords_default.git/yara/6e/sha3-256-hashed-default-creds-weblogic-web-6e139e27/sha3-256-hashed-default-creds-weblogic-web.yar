rule sha3_256_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bde90c25ad6d01ace5ae0cfc9d17437bb7741f698a922de35f8e624b1af93a00"
    $a1="bde90c25ad6d01ace5ae0cfc9d17437bb7741f698a922de35f8e624b1af93a00"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a6="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a7="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a8="720a899ab40d960db60a5381aa73c573b166b68c3c88e861e5310b102b55b13c"
    $a9="720a899ab40d960db60a5381aa73c573b166b68c3c88e861e5310b102b55b13c"
    $a10="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a11="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a12="abdbd5fe0eafa959a296ffa0b3dd55c7413a4f1917b5fe5599eeb0c361501b56"
    $a13="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a14="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a15="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a16="ee2ba9a8201ef4ce1c2f294358095cf2723b561e45bcc8730fadadee6d6a8164"
    $a17="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a18="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a19="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a20="10821183917e589e180bfce385e7e0e661929c4069c4057c0f463e73d0d478c2"
    $a21="10821183917e589e180bfce385e7e0e661929c4069c4057c0f463e73d0d478c2"
    $a22="3b14cc7ebef3e3ce26ddf7a2add934339ebde92b7bad2883541d2d46c4467df9"
    $a23="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
    $a24="ee2ba9a8201ef4ce1c2f294358095cf2723b561e45bcc8730fadadee6d6a8164"
    $a25="8de84c9469b59d778660a26417212cfaa5deac721dae8193336d806f07d53ee6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}