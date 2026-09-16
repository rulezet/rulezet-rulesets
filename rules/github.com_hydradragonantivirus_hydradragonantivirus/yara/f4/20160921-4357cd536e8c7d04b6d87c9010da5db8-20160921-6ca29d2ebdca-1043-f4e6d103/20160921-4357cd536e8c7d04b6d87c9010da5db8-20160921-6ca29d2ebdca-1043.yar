rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_6ca29d2ebdca_1043 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash3       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash4       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1  = "(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";}" ascii
    $s2  = "),(function f000(){return \"ZIi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3  = "n f000(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"L" ascii
    $s4  = "(){return \"Vj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s5  = "0(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";}" ascii
    $s6  = "ion f000(){return \"Yv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7  = "rn \"ZGq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s8  = "ion f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s9  = ";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s10 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return" ascii
    $s11 = "unction f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYs\";})(),(function f000(){re" ascii
    $s12 = "rn \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s13 = " f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s14 = " \"Tn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s15 = "){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s16 = "on f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s17 = " \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s18 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"BMj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}