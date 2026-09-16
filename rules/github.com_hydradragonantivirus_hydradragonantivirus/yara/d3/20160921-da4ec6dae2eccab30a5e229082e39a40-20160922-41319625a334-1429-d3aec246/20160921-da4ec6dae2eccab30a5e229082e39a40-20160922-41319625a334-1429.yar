rule _20160921_da4ec6dae2eccab30a5e229082e39a40_20160922_41319625a334_1429 {
  meta:
    description = "datamaliciousorder - from files 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash2       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1  = "on f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2  = "){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})" ascii
    $s3  = ",(function f000(){return \"Qa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s4  = "on f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii
    $s5  = "urn \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s6  = "(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000" ascii
    $s7  = "000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\"" ascii
    $s8  = "unction f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s9  = "o\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s10 = "\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function" ascii
    $s11 = " \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s12 = "GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s13 = "\"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(functio" ascii
    $s14 = "00(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}