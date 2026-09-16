rule sig_20160309_d1089059bf95233c458c58de7dd585d2 {
  meta:
    description = "datamaliciousorder - file 20160309_d1089059bf95233c458c58de7dd585d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22f69ac2e1861b59d0ec2ba16bdfbffec87368be15735d6f9ba7d8dfbbdbb79a"

  strings:
    $s1  = "uSQzz.open(Dqklm,VrUNI,false);" fullword ascii
    $s2  = "var jA = true  , zvhq = yPq[7] + yPq[9] + yPq[11];" fullword ascii
    $s3  = "return kuZTTHB[0] + kuZTTHB[2] + kuZTTHB[4] + \".F\" + kuZTTHB[7] + kuZTTHB[9] + kuZTTHB[12] + kuZTTHB[14];" fullword ascii
    $s4  = "var kuZTTHB = \"Sc hATxIWX r bVbCYKtHO ipting GxtOqbF kMK ile VJvWmrWYruwoIS System sB zfvVf Obj GHVMlU ect bcBybln\".split(\" " ascii
    $s5  = "function JVcY(uSQzz,VrUNI,Dqklm) {" fullword ascii
    $s6  = "var yPq = (\"2.XMLHTTP uIZWMIF UEWUD XML ream St ZFOsFEHG AD AebJxZn O Wsyo D\").split(\" \");" fullword ascii
    $s7  = "function Rjso(EIhgY) {" fullword ascii
    $s8  = "function fdgqOvpq(Nhq) {" fullword ascii
    $s9  = "return EIhgY.status;" fullword ascii
    $s10 = "function sjwDQXg(OcML) {" fullword ascii
    $s11 = "function KCExyuKZC(aFbbW,MBNuT,xxsZG,SYgZ) {" fullword ascii
    $s12 = "return dBYt.responseBody;" fullword ascii
    $s13 = "function QRsa(hRXnc) {" fullword ascii
    $s14 = "function gsDg(xnOfQ) {" fullword ascii
    $s15 = "return di.ExpandEnvironmentStrings(OdCXb[6]+OdCXb[7]+OdCXb[8]);" fullword ascii
    $s16 = "return KCleM;" fullword ascii
    $s17 = "function OoZEjVGQQ(hxhYjZrsEcE) {" fullword ascii
    $s18 = "if (xnOfQ == 731-531){return true;} else {return false;}" fullword ascii
    $s19 = "return tauYtkd" fullword ascii
    $s20 = "function iapv(irWUH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}