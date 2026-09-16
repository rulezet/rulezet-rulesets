rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c6572694e517_3109 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash3       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "unction f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s2 = "\"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(functi" ascii
    $s3 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f" ascii
    $s4 = "ction f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s5 = "n \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s6 = "return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii
    $s7 = "unction f000(){return \"NYh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"OMd\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}