rule sig_20160308_ba454655b9cb2eaa49ca1ed4f103f052 {
  meta:
    description = "datamaliciousorder - file 20160308_ba454655b9cb2eaa49ca1ed4f103f052.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "932699c0c44722e6a9f0e46e6b468990f574dc37b800beff808865bb3021e082"

  strings:
    $s1  = "var NV = true  , RzXJ = Mao[7] + Mao[9] + Mao[11];" fullword ascii
    $s2  = "return msiSgQq[0] + msiSgQq[2] + msiSgQq[4] + \".F\" + msiSgQq[7] + msiSgQq[9] + msiSgQq[12] + msiSgQq[14];" fullword ascii
    $s3  = "var msiSgQq = \"Sc OGVeNAZ r KRiQbjQEa ipting SnMzrJs OQs ile uhfOnrVkqfDtaY System YX uOPUx Obj HMaqbP ect cpVxAsq\".split(\" " ascii
    $s4  = "KptRb.open(RfJdQ,jLkGM,false);" fullword ascii
    $s5  = "var Mao = (\"2.XMLHTTP NrgxheK DomKa XML ream St CqQeZLlh AD UlQcmCS O lVud D\").split(\" \");" fullword ascii
    $s6  = "function qMAbvBIGU(rvSvThKrQaM) {" fullword ascii
    $s7  = "function sDhf(KptRb,jLkGM,RfJdQ) {" fullword ascii
    $s8  = "function wpXm(ZqHlb) {" fullword ascii
    $s9  = "function jclEUtun(qqK) {" fullword ascii
    $s10 = "if (lhfZm == 365-165){return true;} else {return false;}" fullword ascii
    $s11 = "return YUqyf.status;" fullword ascii
    $s12 = "function wTvYTuV(lSwh) {" fullword ascii
    $s13 = "function ARAK(EHFaH) {" fullword ascii
    $s14 = "function uiQNu(SEdbmc) {" fullword ascii
    $s15 = "function rNgG(lhfZm) {" fullword ascii
    $s16 = "if (LNKhY > 190658-674){return true;} else {return false;}" fullword ascii
    $s17 = "function Qyqb(YUqyf) {" fullword ascii
    $s18 = "function jUaRaPbl() {" fullword ascii
    $s19 = "return KFbyq;" fullword ascii
    $s20 = "return qqK.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}