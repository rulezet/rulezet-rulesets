rule sig_20160307_00fd9faf2cde96d30d52274ce16e5a43 {
  meta:
    description = "datamaliciousorder - file 20160307_00fd9faf2cde96d30d52274ce16e5a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8306ec98fb2562eedf6381d78d04803ee5a0c21a3660e98275f7c3dab96f85d"

  strings:
    $s1  = "return DfYNAVk[0] + DfYNAVk[2] + DfYNAVk[4] + \".F\" + DfYNAVk[7] + DfYNAVk[9] + DfYNAVk[12] + DfYNAVk[14];" fullword ascii
    $s2  = "var sH = true  , Goww = Fxq[7] + Fxq[9] + Fxq[11];" fullword ascii
    $s3  = "hTJXv.open(ffOsw,Indnn,false);" fullword ascii
    $s4  = "var Fxq = (\"2.XMLHTTP LKGLViL kAkqB XML ream St CjBjxYQm AD cbiSgfY O PhSw D\").split(\" \");" fullword ascii
    $s5  = "return zJZw.responseBody;" fullword ascii
    $s6  = "return new ActiveXObject(jCkQjD);" fullword ascii
    $s7  = "function offM(hTJXv,Indnn,ffOsw) {" fullword ascii
    $s8  = "Kqg = K; break; " fullword ascii
    $s9  = "return OQ.ExpandEnvironmentStrings(VAbvE[6]+VAbvE[7]+VAbvE[8]);" fullword ascii
    $s10 = "function HLDj(QmwSb) {" fullword ascii
    $s11 = "return bTQla.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s12 = "function MWtqjkRM() {" fullword ascii
    $s13 = "function BtIf(iwRKc) {" fullword ascii
    $s14 = "function dOcJt(jCkQjD) {" fullword ascii
    $s15 = "if (QmwSb == 832-632){return true;} else {return false;}" fullword ascii
    $s16 = "function FcodmOrZh(rqWkj,NcWkC,MJscM,mPPK) {" fullword ascii
    $s17 = "function PkKLSjBDE(CMpFlNCFHfH) {" fullword ascii
    $s18 = "return iwRKc.status;" fullword ascii
    $s19 = "if(K>=Y.length) {break;}" fullword ascii
    $s20 = "function ZnKb(piHyu,vCser) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}