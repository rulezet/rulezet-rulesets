rule sha256_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a1="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a2="2aa10c7e1ba8d76746634bdb832005103645e62913f9f5cfe621e8f088915abf"
    $a3="0b8e9e995d8d77f1e4770f0f79665aee6f3f70247b3735422daba73df4c3096f"
    $a4="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a5="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a6="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a7="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a8="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a9="2aa10c7e1ba8d76746634bdb832005103645e62913f9f5cfe621e8f088915abf"
    $a10="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a11="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a12="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a13="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a14="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a15="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a16="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a17="8b2085f74dfa9c78a23b7d573c23d27d6d0b0e50c82a9b13138b193325be3814"
    $a18="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a19="092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d"
    $a20="2d084342694e7d6b7ad38afc89264915449338d3092356ebf9e5482c4a52213d"
    $a21="9f69998560dcfd8016442e0a32e959191df095817a164ce844c64ec5a8b0cc1b"
    $a22="715dc8493c36579a5b116995100f635e3572fdf8703e708ef1a08d943b36774e"
    $a23="10fd874b68dad080ed706762c8e163dabb20514bddae38fb159c56f714a3b143"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}