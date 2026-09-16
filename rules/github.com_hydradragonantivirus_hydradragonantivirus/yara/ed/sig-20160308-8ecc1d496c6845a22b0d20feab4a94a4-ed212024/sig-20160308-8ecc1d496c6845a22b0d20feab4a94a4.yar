rule sig_20160308_8ecc1d496c6845a22b0d20feab4a94a4 {
  meta:
    description = "datamaliciousorder - file 20160308_8ecc1d496c6845a22b0d20feab4a94a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d425e9f7b5a011dbfaeeb7e816dba216c41a21e54e91bc46b5f4e63d7bbcf138"

  strings:
    $s1  = "var IB = true  , nKxB = PKg[7] + PKg[9] + PKg[11];" fullword ascii
    $s2  = "return YnOqdgh[0] + YnOqdgh[2] + YnOqdgh[4] + \".F\" + YnOqdgh[7] + YnOqdgh[9] + YnOqdgh[12] + YnOqdgh[14];" fullword ascii
    $s3  = "var PKg = (\"2.XMLHTTP tInQkvW DrwXz XML ream St FBcQHYlz AD lrzIDkT O zpTy D\").split(\" \");" fullword ascii
    $s4  = "lPtFX.open(FbjTD,swYIt,false);" fullword ascii
    $s5  = "var YnOqdgh = \"Sc bykhIgG r dOKFEMhBz ipting mTiCFuc IEC ile RRFyAzMkFttoQm System hO HGGCj Obj jMVJzl ect LgaaOwd\".split(\" " ascii
    $s6  = "function vShp(zfbuO) {" fullword ascii
    $s7  = "return yLBfZ;" fullword ascii
    $s8  = "function NvfMBpkAt(EpeDg,uBLHl,jrana,TBpX) {" fullword ascii
    $s9  = "return aifi.responseBody;" fullword ascii
    $s10 = "function hZkU(CSdGa) {" fullword ascii
    $s11 = "function WHpJ(SFeng) {" fullword ascii
    $s12 = "if(r>=G.length) {break;}" fullword ascii
    $s13 = "function YKWU(hwwqZ) {" fullword ascii
    $s14 = "return new ActiveXObject(NUbazD);" fullword ascii
    $s15 = "TQu = r; break; " fullword ascii
    $s16 = "if (CSdGa > 160192-340){return true;} else {return false;}" fullword ascii
    $s17 = "function ePiB(bIblT) {" fullword ascii
    $s18 = "function HRmFMChL(cHz) {" fullword ascii
    $s19 = "function JhKYs(NUbazD) {" fullword ascii
    $s20 = "function avuQqQk(aifi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}