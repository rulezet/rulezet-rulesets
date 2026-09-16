rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c6572694e517_5 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1  = " f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s2  = "ion f000(){return \"Wh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"" ascii
    $s3  = "000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Qz" ascii
    $s4  = "n f000(){return \"MJq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5  = "f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"W" ascii
    $s6  = "tion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return" ascii
    $s7  = "0(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";}" ascii
    $s8  = "eturn \"EZu\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(" ascii
    $s9  = ";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f0" ascii
    $s10 = "ction f000(){return \"Vj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s11 = "unction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s12 = "f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DI" ascii
    $s13 = "f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj" ascii
    $s14 = "){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Vj\";})" ascii
    $s15 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){retu" ascii
    $s16 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f" ascii
    $s17 = "eturn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s18 = "000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj" ascii
    $s19 = "\"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s20 = "turn \"Nx\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mt\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}