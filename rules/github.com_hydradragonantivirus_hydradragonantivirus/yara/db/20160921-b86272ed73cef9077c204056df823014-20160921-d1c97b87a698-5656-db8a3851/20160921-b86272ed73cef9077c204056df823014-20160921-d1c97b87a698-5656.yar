rule _20160921_b86272ed73cef9077c204056df823014_20160921_d1c97b87a698_5656 {
  meta:
    description = "datamaliciousorder - from files 20160921_b86272ed73cef9077c204056df823014.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "a\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function" ascii
    $s2 = "n \"DNa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s3 = "{return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s4 = "(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000" ascii
    $s5 = "ction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}