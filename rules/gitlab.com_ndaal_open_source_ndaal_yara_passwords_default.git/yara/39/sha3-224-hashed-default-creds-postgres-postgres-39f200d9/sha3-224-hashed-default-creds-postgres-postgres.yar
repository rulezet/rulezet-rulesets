rule sha3_224_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="7dba765e4642eb08f384328cd06aba95b33e9a872ed559bf50131458"
    $a5="4f7ca2890fb7312749158a56dced45a3416bd50e3b2a21fbe73ce370"
    $a6="602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"
    $a7="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a8="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a9="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a10="d1e135617b1dfeaf29c767697e054083fb4cab90682fc59e41363bf3"
    $a11="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a12="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a13="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a14="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a15="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a16="20cadf40052adfc3b0cefb9b367641475e5573b3c6a7a1f2cdf83384"
    $a17="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a18="daf90d1eb720d4863cc6f87b96ca0b82f908545508d89caa34c7fc8f"
    $a19="f90cbe54b798f519795f11f89e6b80f5c505de2f41701e6742167297"
    $a20="daf90d1eb720d4863cc6f87b96ca0b82f908545508d89caa34c7fc8f"
    $a21="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a22="c317c0ab11d7c71a4c7286471e7c9be31c2f79ab18d211ccd8a48bbd"
    $a23="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}