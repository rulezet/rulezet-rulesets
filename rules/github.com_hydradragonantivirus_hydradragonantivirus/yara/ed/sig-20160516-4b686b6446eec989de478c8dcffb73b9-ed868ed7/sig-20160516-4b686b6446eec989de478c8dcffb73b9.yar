rule sig_20160516_4b686b6446eec989de478c8dcffb73b9 {
  meta:
    description = "datamaliciousorder - file 20160516_4b686b6446eec989de478c8dcffb73b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f8d1c96611f9c0d86000161a2fdcd6490390f1364d396035baba2d732cc8caf"

  strings:
    $s1  = "while (IOYABWM < wbkad - (5808 + 1195 - 7001)) {" fullword ascii
    $s2  = "pdbVQOb(false);" fullword ascii
    $s3  = "return faSR;" fullword ascii
    $s4  = "var WUfsrH = false;" fullword ascii
    $s5  = "return PpZoN;" fullword ascii
    $s6  = "var dNjQ = true;" fullword ascii
    $s7  = "function tIgi() {" fullword ascii
    $s8  = "function usupkGB(cvrBAfv) {" fullword ascii
    $s9  = "return MBkwCSZc;" fullword ascii
    $s10 = "function QtMeVn() {" fullword ascii
    $s11 = "function QCxs() {" fullword ascii
    $s12 = "return lGtdx;" fullword ascii
    $s13 = "return DHnH;" fullword ascii
    $s14 = "return omlQ;" fullword ascii
    $s15 = "function DbZ() {" fullword ascii
    $s16 = "function oYYLr() {" fullword ascii
    $s17 = "return aHDAtlD;" fullword ascii
    $s18 = "if (EjC == false) {" fullword ascii
    $s19 = "return CxhdID;" fullword ascii
    $s20 = "return DFYhviWN;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}