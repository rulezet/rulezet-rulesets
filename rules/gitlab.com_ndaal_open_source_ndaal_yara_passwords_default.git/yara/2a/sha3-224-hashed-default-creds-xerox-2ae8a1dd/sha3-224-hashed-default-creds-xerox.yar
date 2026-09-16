rule sha3_224_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="92126b5f10eb58e6c88b6b5c8b47da1967843694bf61417ff8a98a9b"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="bf5b5c7f32e8b4ae23803af71b0f1c6eab4508378e00ea966d652979"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="8d5e24056d144fb0c63f871536f662e41be1e107c88ef7bb5a75aea4"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="92126b5f10eb58e6c88b6b5c8b47da1967843694bf61417ff8a98a9b"
    $a9="a499dc297b89876e6a2645927c301fc0349118363aa0e7e7db152e5a"
    $a10="11ff8a7c0d7a2ef4c85f82ab8bccf0dc695c34d4e8e151e0751e9d58"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="f18751d561f0172d63a18c94e090333f9d4016f359a1df43d1881f9a"
    $a13="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a14="a855549fc101de3f16de627e8cb4519a632ebbbb8280d1c16b5958c6"
    $a15="d486b6a2b4dc2665ea144fd7c2afd44fe9dac04661d70f9d0f821e3a"
    $a16="1884f849613e913f0dd164ac80b45c7802673ae3452bc43d8724ee45"
    $a17="cfcd4c76eed0f00898a5013d1b6d340de6c24b66e5b1fd4de7e4aecf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}