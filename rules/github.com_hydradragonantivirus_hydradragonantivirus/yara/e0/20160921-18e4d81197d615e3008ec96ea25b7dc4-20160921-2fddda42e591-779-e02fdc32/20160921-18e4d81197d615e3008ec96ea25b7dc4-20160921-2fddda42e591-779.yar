rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_2fddda42e591_779 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_2fddda42e5911e6501568e734d430149.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"

  strings:
    $s1  = "nction f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Sv\";})(),(function f000(){retu" ascii
    $s2  = "(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";" ascii
    $s3  = ";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f" ascii
    $s4  = "function f000(){return \"Km\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s5  = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s6  = "Lk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functi" ascii
    $s7  = "ction f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return" ascii
    $s8  = "ion f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s9  = "(function f000(){return \"Go\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})(),(function f000(){ret" ascii
    $s10 = "){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})" ascii
    $s11 = "(function f000(){return \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s12 = "tion f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){retur" ascii
    $s13 = "(){return \"TKl\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s14 = "Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"TKp\";})(),(functi" ascii
    $s15 = "000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s16 = "})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s17 = "rn \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s18 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})" ascii
    $s19 = "eturn \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()," ascii
    $s20 = "return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OMd\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}