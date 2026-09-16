rule _20160921_24a000738e40009c8bea0a81a0c09cf4_20160921_c1b40d45f00b_1820 {
  meta:
    description = "datamaliciousorder - from files 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash2       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1  = "nction f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s2  = "{return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\";})(" ascii
    $s3  = "Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functio" ascii
    $s4  = "f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s5  = "000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn" ascii
    $s6  = ";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f0" ascii
    $s7  = "turn \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s8  = "){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";" ascii
    $s9  = "\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s10 = "ion f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}