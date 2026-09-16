rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_ca70c2e52231_5055 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash3       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash4       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s2 = "{return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(" ascii
    $s3 = "t\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s4 = "tion f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s5 = "\"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}