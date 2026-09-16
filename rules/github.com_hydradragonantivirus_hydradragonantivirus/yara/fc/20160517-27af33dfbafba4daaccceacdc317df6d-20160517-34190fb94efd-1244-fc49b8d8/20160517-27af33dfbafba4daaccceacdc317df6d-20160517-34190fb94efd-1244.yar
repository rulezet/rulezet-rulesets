rule _20160517_27af33dfbafba4daaccceacdc317df6d_20160517_34190fb94efd_1244 {
  meta:
    description = "datamaliciousorder - from files 20160517_27af33dfbafba4daaccceacdc317df6d.js, 20160517_34190fb94efdaceb04ec4dcbcbf2fca7.js, 20160517_5bdb6577e1609a334c569c0925ee4f41.js, 20160517_615edc3efa00e8cd3779790e2f454d3c.js, 20160517_8189cbb7f4028311a5d11bbd8d532e59.js, 20160517_d22f84d7e5910b92b34542bcd77321ad.js, 20160517_e8fbcb6e76821fe5ffc2d1591b78899f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42660c29d0767a960191a16ffb2ecad13ec1e8c4cb1f0a759157a1b027b6b691"
    hash2       = "1a79a92816139ce41e301ad9767f19e6aff721514f5d948db27fe15d605768de"
    hash3       = "743e004a28a9f017e618c4cb1e65a2ab24227b9c61206a2e72f6768d896f77bf"
    hash4       = "ae3879ee75e4658290b65c338f61b1e495a7b724cb4c0352692874acaedc1144"
    hash5       = "7451bb0921e4550137798f4975b9847ca5cfa5d3376becbcb2c66e9fe397b59b"
    hash6       = "e93e58a946eaf844955756f089ea3351166a78c4cf4ae1bcee5a7d56de79ea08"
    hash7       = "0990bdcb0e8fe28df391af65a3bd1c9c18459d6ddee3b0c7e8b635b92a6dba5a"

  strings:
    $s1 = "function Scott /* b  */(accinp0 /* b  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* b  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* b  */ = (123, Turkey); return devel0 /* b  */;};" fullword ascii
    $s4 = "DENMARK1 /* b  */= true;/* b  */" fullword ascii
    $s5 = "place = /* b  */(/* b  */\"noitisop\").split(''/* b  */).reverse(/* b  */).join('');" fullword ascii
    $s6 = "function Scott /* b  */(accinp0 /* b  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}