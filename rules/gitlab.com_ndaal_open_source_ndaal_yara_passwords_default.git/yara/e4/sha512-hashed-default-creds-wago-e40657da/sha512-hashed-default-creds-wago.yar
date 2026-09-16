rule sha512_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6d3e73a23b4b12cd7fb52544740f5b240581f25a7292c003928403f812620799f24a179fcda4b7aebe74565df4d2ce5f528b24b5dbc3baa227d5582e32e0c13"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a3="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a4="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a5="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a6="887ad6a742d43ad98d149b3c7f3de605c9bdf43dc148e4519cbfa021833bdba78d2a19eaf7dbd4158447651ee7f75dbcbc1f3a3199137c77f6af066216161397"
    $a7="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a8="16f4e2594a05896ab88c07745e74bd6d4343d11b01afba030cba6a0ece87085593e7f21b0044bdaf15b8ec05fde30eb1981c77b3de5e4f7d9d058c4e1f492ecd"
    $a9="26857f0074d5e2393884b7b1aa9efc5e919d1111cef6e3b06c13dba5119cf882c317f8f4987a30e533eb786f138a876df4b3258a195bee819692600b7b6236bf"
    $a10="b6d3e73a23b4b12cd7fb52544740f5b240581f25a7292c003928403f812620799f24a179fcda4b7aebe74565df4d2ce5f528b24b5dbc3baa227d5582e32e0c13"
    $a11="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}