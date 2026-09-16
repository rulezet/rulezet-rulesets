rule sha384_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="708a30d296765478ea9d0dc885a9dd2a91910a657b9b08056b633b4fd29ef02dc9f1de6f9f857ce34068578e604793fa"
    $a1="ed05253147bb1264fd8ba2ec17dc5aad55ebce753a06729fa519e70343d102950f79d5866d9023f112f7bf3cbeaa3391"
    $a2="a6b8aca84fd5ea2e59792a72a1e3cc252378cf3f355461e4ad79644490bd5dcdee1d6513099ff20f91b9d6d2e4faa556"
    $a3="a6b8aca84fd5ea2e59792a72a1e3cc252378cf3f355461e4ad79644490bd5dcdee1d6513099ff20f91b9d6d2e4faa556"
    $a4="eca996aae3580145a6c6b631d11e3e776d3ee19219dd6ba5a9719c447795aa9a6b9424fbe24baa66fa866039279de904"
    $a5="eca996aae3580145a6c6b631d11e3e776d3ee19219dd6ba5a9719c447795aa9a6b9424fbe24baa66fa866039279de904"
    $a6="ec0a06a45c12a6e9d4a649587e8fccbd77ebbd8d040ed2b949af716e713c50a500645dab58de3cef98e7e099c8f92bfc"
    $a7="ec0a06a45c12a6e9d4a649587e8fccbd77ebbd8d040ed2b949af716e713c50a500645dab58de3cef98e7e099c8f92bfc"
    $a8="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a9="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a10="c2df787d00aae590a18b7140c03cf67206d224ef555415356f7d78451e88a4c37de08b868ac3da9ae948f99dae62ffa7"
    $a11="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a12="8720d41ea20604e93d759b6a47ad5238284daefca8da7ed3f849cd7dcbb2fb599ed421787be148e26a357e794f2c020a"
    $a13="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
    $a14="4cb1bf67418f5c820e9be529c84ab800c926cb284de13a6d0e574c01a5951c932f6eb782d6d16eb419504ce60ecc329a"
    $a15="b7af2a619027be2e1d409b7e68c714d3f33a436b8e58aeb11b57a598e095f4f1b5e897ca56340914662677a5d7e6abc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}