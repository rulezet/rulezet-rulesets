rule sig_20160307_4beec45e897ef890ec7d619a02c51e16 {
  meta:
    description = "datamaliciousorder - file 20160307_4beec45e897ef890ec7d619a02c51e16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "305bb3092543e43a99178b4caf7625fac28056a9244f32ec198aa598e2b1019f"

  strings:
    $s1  = "return BSrgYab[0] + BSrgYab[2] + BSrgYab[4] + \".F\" + BSrgYab[7] + BSrgYab[9] + BSrgYab[12] + BSrgYab[14];" fullword ascii
    $s2  = "var po = true  , xhtn = uKK[7] + uKK[9] + uKK[11];" fullword ascii
    $s3  = "var BSrgYab = \"Sc FqXItUh r wvjymuiIA ipting ozIetpd Hyr ile nLzCogWynEvoWL System tb AfKSQ Obj tUCVkP ect HTlsXqG\".split(\" " ascii
    $s4  = "var uKK = (\"2.XMLHTTP CDQDbXl htBDz XML ream St DjPnGVJC AD ExtdkZh O urxO D\").split(\" \");" fullword ascii
    $s5  = "jSMPN.open(NgUfT,YmRZO,false);" fullword ascii
    $s6  = "if (mcYuv == 1174-974){return true;} else {return false;}" fullword ascii
    $s7  = "function jNMq(udIJd) {" fullword ascii
    $s8  = "function atwY(Uszjs,PTmrh) {" fullword ascii
    $s9  = "if (kwnHa > 172235-829){return true;} else {return false;}" fullword ascii
    $s10 = "function VPRiZAwu(kxR) {" fullword ascii
    $s11 = "return gxoZq.status;" fullword ascii
    $s12 = "function vSxY(RtQcP) {" fullword ascii
    $s13 = "function YCRX(jSMPN,YmRZO,NgUfT) {" fullword ascii
    $s14 = "function lCfAzlJ(LwPS) {" fullword ascii
    $s15 = "return new ActiveXObject(pvrQly);" fullword ascii
    $s16 = "function qTXhaqmT() {" fullword ascii
    $s17 = "if (((new Date())>0,7373118888)) {" fullword ascii
    $s18 = "return Jl.ExpandEnvironmentStrings(WVjWP[6]+WVjWP[7]+WVjWP[8]);" fullword ascii
    $s19 = "if(B>=x.length) {break;}" fullword ascii
    $s20 = "iMl = B; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}