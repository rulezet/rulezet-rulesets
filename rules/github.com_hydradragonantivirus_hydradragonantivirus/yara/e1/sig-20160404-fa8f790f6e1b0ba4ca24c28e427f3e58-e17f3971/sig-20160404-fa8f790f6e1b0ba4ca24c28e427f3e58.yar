rule sig_20160404_fa8f790f6e1b0ba4ca24c28e427f3e58 {
  meta:
    description = "datamaliciousorder - file 20160404_fa8f790f6e1b0ba4ca24c28e427f3e58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "590ef9b0161f22fd588d85d7a3d9ba3f4335a0b41eee979275d58ac0dbe2dba3"

  strings:
    $s1  = "var Ki = true  , tzET = Fzk[7] + Fzk[9] + Fzk[11];" fullword ascii
    $s2  = "return oBuUfQJ[0] + oBuUfQJ[2] + oBuUfQJ[4] + \".F\" + oBuUfQJ[7] + oBuUfQJ[9] + oBuUfQJ[12] + oBuUfQJ[14];" fullword ascii
    $s3  = "var Fzk = (\"2.XMLHTTP oIXCvWo sLKur XML ream St xLaIDkEa AD xuVuwCR O AYcx D\").split(\" \");" fullword ascii
    $s4  = "aiMr.open(QCpKy,ShXja,false);" fullword ascii
    $s5  = "var oBuUfQJ = hNvLl(wCmXmpgSey+\" \"+\"System YV NLbRR Obj YygQSv ect XLZPbvn GtpFs\", \" \");" fullword ascii
    $s6  = "if(W>=Z.length) {break;}" fullword ascii
    $s7  = "function VJzP(fMLKf) {" fullword ascii
    $s8  = "function MdZn(HHHba) {" fullword ascii
    $s9  = "function cnkKvCji(fUs) {" fullword ascii
    $s10 = "return WCeO[QxCigL[0]];" fullword ascii
    $s11 = "function DqTFUUX(ozWM,gtraZ) {" fullword ascii
    $s12 = "var xRoDdgg = \"JFNZmN*HFt*pt.S\"+\"hell*asYwxAM*Scri*\";" fullword ascii
    $s13 = "return DqTFUUX(Ra,EEkLe[907-901]+EEkLe[308-301]+EEkLe[354-346]);" fullword ascii
    $s14 = "function MlRYuZdhY(PkKCNhAvBZY) {" fullword ascii
    $s15 = "function QcGB(qHiBf,ShXja,QCpKy) {" fullword ascii
    $s16 = "if (m >= AWiEN.length) {break;}" fullword ascii
    $s17 = "return ANLEmNS;" fullword ascii
    $s18 = "function oMknn(VfxVxl) {" fullword ascii
    $s19 = "function QgeVEQ(TEPN,IvQixY) {" fullword ascii
    $s20 = "function zstN(dVLRU,mRSOm) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}