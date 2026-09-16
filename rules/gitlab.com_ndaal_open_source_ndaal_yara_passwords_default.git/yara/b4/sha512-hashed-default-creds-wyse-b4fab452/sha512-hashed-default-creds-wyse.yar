rule sha512_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d716064bc0e1935ee1b8e66c9991d163307ae05c6a2c8518e750ee3d0c7e23f297ffa7e92f84a9fe718cf4215089c180920868569c11701da34803103737a0ea"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="dd13455b8c4fe096351cb50144ecaa8cd132a70f120e5800b2bfa4796a73215e7ecbaea693a993300d3d7b0d885a25329eb4da9c4bf525e1dec415dada427fb0"
    $a3="47dac71b14bc4892f418563c2c44efd0d20df0588e2b6b65ed611dcda0f99e64b1373b57528ce2ef9a8d9f63d58e88c5ded5ad88032afec577789ce01dc6c43e"
    $a4="d633fb1d21b919712985b307728e1cae1220c75db85bcf8c11e50ddcd946b87618232618e01d22f258ea0b1febc06d75d9a76760736ad63494f18f6a0cb68882"
    $a5="dff2bc14e152889058764e1d58a0d7cd41509feb70d986f9757eff8947a0321a7710d97019a79241f0e5caf9f718e12d4950b3beb852f0ab78954a0cc9915d93"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}