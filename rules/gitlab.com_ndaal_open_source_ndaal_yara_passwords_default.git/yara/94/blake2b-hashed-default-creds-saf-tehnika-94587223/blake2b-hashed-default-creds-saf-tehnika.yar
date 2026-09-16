rule blake2b_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2192112f9ead44efa931eb44022a832d9da272a961913b1199d6727a28f505ee4264f4fad018f55e7bb5fd94945bc75e9253e6339eaa566abb6bf16c6fe7636"
    $a1="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a2="bd3e2b37a678e8fc512bbaf5a948830a0fd1b379b96d652aee301965d049e84030bd90810a27da066086f5ee79828dc7e351a371ea70a662a22478d5eaf345d6"
    $a3="1cf06fe11fd11b8c2d217218eb54d0f8139a8a42aa9b2a39f075f483e0d4973cd3ce6a16ea6482280dcdeae6041192a97ceef6e50a7f01e90f81d4df4efcad11"
    $a4="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a5="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a6="662bd758e37a238307d407df11f2807d2c0634f1c007cfb1d6a4925b4d05fe34946cf7ebdb5c029bbc7b061ea198e51a4ad890e0ee95aab398b3ac13e7ec6695"
    $a7="1645ae4b5b2eb6fbe61362cd6d7a1fc4862db293d0e6f24d62731e836b5c42c3c38a80a370036c992ef1b42c8b2dfb1ff7df21589826b40ff393301f51459776"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}