rule sig_20160513_391686c3afe1ae6c8bbc57f0a69b9792 {
  meta:
    description = "datamaliciousorder - file 20160513_391686c3afe1ae6c8bbc57f0a69b9792.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad701f6eb5dcbfe8bb0755cc0d26dfc40e49d731162e445ef5820c3a99168028"

  strings:
    $s1  = "var gwrNUxx = TWIN(xSYJufN, ajAI + (2426 - 2424));" fullword ascii
    $s2  = "var arRS = TWIN(xSYJufN, ajAI + (7161 - 7160));" fullword ascii
    $s3  = "while (ajAI < JMOV - (2426 - 2424)) {" fullword ascii
    $s4  = "OQFQFGx = TWIN(xSYJufN, mQNKx) + VDaquv;" fullword ascii
    $s5  = "if (KeY == false) {" fullword ascii
    $s6  = "function ZyvNOn(KeY, xurU) {" fullword ascii
    $s7  = "function xIGAC(LYACmD) {" fullword ascii
    $s8  = "return ZTzsOH;" fullword ascii
    $s9  = "function ZSLLyac() {" fullword ascii
    $s10 = "return PbHz;" fullword ascii
    $s11 = "return JBivWUfk;" fullword ascii
    $s12 = "return fCtXTQw;" fullword ascii
    $s13 = "var VDaquv = TWIN(xSYJufN, cHBh);" fullword ascii
    $s14 = "return FfNRqw;" fullword ascii
    $s15 = "return WNymShlb;" fullword ascii
    $s16 = "var WOZwqq = true;" fullword ascii
    $s17 = "var snQSVBG = TWIN(xSYJufN, uYmn);" fullword ascii
    $s18 = "return PQJHizw;" fullword ascii
    $s19 = "function UEy() {" fullword ascii
    $s20 = "return CvENre;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}