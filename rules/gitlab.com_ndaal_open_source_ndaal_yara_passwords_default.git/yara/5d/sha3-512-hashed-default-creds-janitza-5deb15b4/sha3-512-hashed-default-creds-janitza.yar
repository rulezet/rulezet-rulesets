rule sha3_512_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3454a88a4ad5b7c42bfb8c89e143c3834ab3b3cf44fa2471de97781bec510dfe96e7809fd7dbd837900493d51a1f0ce7204593b1d81fd6654be6e01cc6b8d4e6"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="3454a88a4ad5b7c42bfb8c89e143c3834ab3b3cf44fa2471de97781bec510dfe96e7809fd7dbd837900493d51a1f0ce7204593b1d81fd6654be6e01cc6b8d4e6"
    $a3="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a4="b22ec99e32ef6a5330d378ab0a170c9b0025b400e33b302851a18233448f176af52c98d62cae41195edb76c15363162a10c218330d82f3473bd322c5765fa10c"
    $a5="18777233cda4eaedadc4b6b1afcaa7968f7c8b048ed63a1a0ffa1141a2050213f9319c543e103dc9bb3079cca9878d55365735c69b9a9ffb321924a2d6a6f5a8"
    $a6="3454a88a4ad5b7c42bfb8c89e143c3834ab3b3cf44fa2471de97781bec510dfe96e7809fd7dbd837900493d51a1f0ce7204593b1d81fd6654be6e01cc6b8d4e6"
    $a7="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}