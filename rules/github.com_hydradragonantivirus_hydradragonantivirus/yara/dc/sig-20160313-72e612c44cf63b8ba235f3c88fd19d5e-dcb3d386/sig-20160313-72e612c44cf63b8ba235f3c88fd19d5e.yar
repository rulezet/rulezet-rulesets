rule sig_20160313_72e612c44cf63b8ba235f3c88fd19d5e {
  meta:
    description = "datamaliciousorder - file 20160313_72e612c44cf63b8ba235f3c88fd19d5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5256192075a78fcf412a1580b3291a9a6851dd67b746d72b939f3fe6f425ff7"

  strings:
    $s1  = "return WAmCOhS[0] + WAmCOhS[2] + WAmCOhS[4] + \".F\" + WAmCOhS[7] + WAmCOhS[9] + WAmCOhS[12] + WAmCOhS[14];" fullword ascii
    $s2  = "var gQ = true  , EUfN = dTt[7] + dTt[9] + dTt[11];" fullword ascii
    $s3  = "YxVYS.open(yviWd,LUzyk,false);" fullword ascii
    $s4  = "var WAmCOhS = \"Sc vClnBpz r UUCcmador ipting GjOuXxL CRn ile VfzEZfWWjQATCD System HV Momsj Obj fWQdLy ect dKsAKGs\".split(\" " ascii
    $s5  = "var dTt = (\"2.XMLHTTP FqYkvjd chKQm XML ream St NldrnCER AD dMvuusP O jwcR D\").split(\" \");" fullword ascii
    $s6  = "function vFYZwAS(mPum,axDkL) {" fullword ascii
    $s7  = "function lVJwN(eNFtge) {" fullword ascii
    $s8  = "return Ssq.size;" fullword ascii
    $s9  = "return new ActiveXObject(mAyVnG);" fullword ascii
    $s10 = "function pZTy(imwCG) {" fullword ascii
    $s11 = "return eNFtge.position=931-931;" fullword ascii
    $s12 = "if (bwlOe == 592-392){return true;} else {return false;}" fullword ascii
    $s13 = "function Bgjc(WAzXk) {" fullword ascii
    $s14 = "function JRuG(TVuYd) {" fullword ascii
    $s15 = "return RYUQI;" fullword ascii
    $s16 = "function mrpB(ECKoe,rtXyJ) {" fullword ascii
    $s17 = "function vyMTugG(aGuP) {" fullword ascii
    $s18 = "return aGuP.responseBody;" fullword ascii
    $s19 = "if (hdYMU > 188037-998){return true;} else {return false;}" fullword ascii
    $s20 = "function JqLK(bwlOe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}