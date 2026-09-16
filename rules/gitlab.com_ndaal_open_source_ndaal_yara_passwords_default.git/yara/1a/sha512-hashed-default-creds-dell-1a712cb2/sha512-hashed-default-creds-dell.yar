rule sha512_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a71e2cf7a3235dbea0d1f9a7a11518c674c299ff7cee2b4e8d9fbf531e3d1c5dd9f9ec9162113ecadfa92175a64c523fdbb27f38def2a2b591adb07497fb1fd1"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="11a53dda6bbd9ea277c1a4209280859347635f36a05df8905eb8d46f049048d57785e9b364e3a3b70473feabe1ec917dd54efc8c73c85831ae1f5e8816471bc4"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="47f4b1fd9ef0b44453e263c33807e9d8376f99f80b95f9e6a997f02a62dcefd8a8cda9f4b40af5011b59a92e0f5df9e9e18a15c943176fe6a48c9a34f5c08b02"
    $a9="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a10="d633fb1d21b919712985b307728e1cae1220c75db85bcf8c11e50ddcd946b87618232618e01d22f258ea0b1febc06d75d9a76760736ad63494f18f6a0cb68882"
    $a11="dff2bc14e152889058764e1d58a0d7cd41509feb70d986f9757eff8947a0321a7710d97019a79241f0e5caf9f718e12d4950b3beb852f0ab78954a0cc9915d93"
    $a12="d716064bc0e1935ee1b8e66c9991d163307ae05c6a2c8518e750ee3d0c7e23f297ffa7e92f84a9fe718cf4215089c180920868569c11701da34803103737a0ea"
    $a13="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a14="dd13455b8c4fe096351cb50144ecaa8cd132a70f120e5800b2bfa4796a73215e7ecbaea693a993300d3d7b0d885a25329eb4da9c4bf525e1dec415dada427fb0"
    $a15="47dac71b14bc4892f418563c2c44efd0d20df0588e2b6b65ed611dcda0f99e64b1373b57528ce2ef9a8d9f63d58e88c5ded5ad88032afec577789ce01dc6c43e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}