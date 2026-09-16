rule sha512_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c463d2e37a30b59654286df095a3dae4dedd3fd70517da07753825a3ad3e4333a62ce2ad5049e6c81d601607d18c901e73dc6e5e3474bc27e6ea0402673b92f1"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="ffe3f4e6ac31e3d5582426003b4fea206d34fefc88252ac2053d17d13440870db2d28b8c0892eb3def5e31cb7d6c545165d86b20ce5a8b38283c68cb04256635"
    $a3="e0562be9d9e7101b8d2402c3855f57b38d96caf6889167e58189d5af876d480c13def121e8f5cc71c5c8029c31b4197e6170610cdc5b10d9361795e2ad584266"
    $a4="e6df825e83e8545a7c9bdc397ca4c87a7272cba9559910c4807d2e45622918fe5267b2154d3719d7585e0464aae07d1d23586f640ed37d41e28897b8f9336e83"
    $a5="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a6="eb1a7891ac4555572e95fc02b111ab89b6f9448b553a446734894545f63bbd70ca9ad4eb872d3d27c30a01e7eed182e014f41c90515b4da71a022a1d1efeba02"
    $a7="edcbca4a3a8b6016adec2851e7a555f0bf7b733016a40f0fc2c9dfba7f608bf19d4785e713388730d7d4a1d78f2ef13be1e55232f5eb30482588fd8b25791c03"
    $a8="21d35c8614e88240fe72493c988e9226b5c6dca03a16a7ba4563cb6a5f79056357864077f9afcb42cf064aae0e6680764280fdd4130316005401f854dbcd6b3e"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a10="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="b8939f8099599c0dbc2a976a6461f2e7ef345da9bcce7b1f71486212cee8c24327f377e7bd5be8b70c55388185e2d5cad29bae2e7c0cb38eb6f744ad7fdda87d"
    $a13="7e18c2c27623ecd2349ed8250ad949781ece7ec955580d56d5903cf087f8590bf86cf2d1d6a543de6517e1647f9ffa0178157bc0a9e0214d89cdd03a95cf73ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}