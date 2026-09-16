rule sig_20160309_054a115db9d7a6b4c05f98147b9ca18f {
  meta:
    description = "datamaliciousorder - file 20160309_054a115db9d7a6b4c05f98147b9ca18f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "869dc8e3b42350d0fa261fa07b99ad6698bdb402c3ac050593b60fd90f8edee7"

  strings:
    $s1  = "return UIxswDq[0] + UIxswDq[2] + UIxswDq[4] + \".F\" + UIxswDq[7] + UIxswDq[9] + UIxswDq[12] + UIxswDq[14];" fullword ascii
    $s2  = "var fJ = true  , OMOu = jyz[7] + jyz[9] + jyz[11];" fullword ascii
    $s3  = "dpImH.open(cksmG,mQgkm,false);" fullword ascii
    $s4  = "var UIxswDq = \"Sc vNSVjbd r llDjGRFxb ipting fQgrqgd DuH ile iZqDHOmLIdGNWz System Jq bdMHb Obj OMKcBz ect iHPMBlP\".split(\" " ascii
    $s5  = "var jyz = (\"2.XMLHTTP sbwVTSM SWVxO XML ream St iPzbIbEo AD CSNJeyQ O eDeq D\").split(\" \");" fullword ascii
    $s6  = "return vCrie;" fullword ascii
    $s7  = "function rxud(dSldU,rFrhq) {" fullword ascii
    $s8  = "return WLdQ.ExpandEnvironmentStrings(cZtZi);" fullword ascii
    $s9  = "function Asrg(dpImH,mQgkm,cksmG) {" fullword ascii
    $s10 = "function XpLwPML(bBKe) {" fullword ascii
    $s11 = "FCE = Y; break; " fullword ascii
    $s12 = "function eDoxRHgm() {" fullword ascii
    $s13 = "function rjPt(uEbQn) {" fullword ascii
    $s14 = "function PWXg(GqyPK) {" fullword ascii
    $s15 = "function ybti(TkrHk) {" fullword ascii
    $s16 = "function jYmyiOOef(WsAYM,PplBD,rHnnN,bFuq) {" fullword ascii
    $s17 = "function mTVt(mKDJc) {" fullword ascii
    $s18 = "if (Q >= mKDJc.length) {break;}" fullword ascii
    $s19 = "return TkrHk.status;" fullword ascii
    $s20 = "function mYNx(UASJx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}