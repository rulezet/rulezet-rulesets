rule sig_20160308_336d659b532a0fe1398efa21a0144b19 {
  meta:
    description = "datamaliciousorder - file 20160308_336d659b532a0fe1398efa21a0144b19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39804987e1fb9e10c52abad05ece16715f5731f763318aba49ec2e9e9b3c53e"

  strings:
    $s1  = "return cCwlnZQ[0] + cCwlnZQ[2] + cCwlnZQ[4] + \".F\" + cCwlnZQ[7] + cCwlnZQ[9] + cCwlnZQ[12] + cCwlnZQ[14];" fullword ascii
    $s2  = "var Wp = true  , lcVw = mSV[7] + mSV[9] + mSV[11];" fullword ascii
    $s3  = "var cCwlnZQ = \"Sc nNYNfGU r WLRPclEuX ipting QBkYxJj FMi ile IDlfExkEUqrPgC System as QhLKe Obj SOUJoe ect AfvKXgI\".split(\" " ascii
    $s4  = "var mSV = (\"2.XMLHTTP tOcDaye yzfSv XML ream St hzfaClJx AD isuYTCM O afxX D\").split(\" \");" fullword ascii
    $s5  = "LPJhJ.open(FtKYn,LVYAJ,false);" fullword ascii
    $s6  = "function Rwvr(LlnOT,ASphE) {" fullword ascii
    $s7  = "return syGZP;" fullword ascii
    $s8  = "RpN = s; break; " fullword ascii
    $s9  = "function oBXn(HSGQp) {" fullword ascii
    $s10 = "function NkgpI(cqcrmx) {" fullword ascii
    $s11 = "function lmUeVeEB(hhI) {" fullword ascii
    $s12 = "return uTPnz.status;" fullword ascii
    $s13 = "if(s>=k.length) {break;}" fullword ascii
    $s14 = "return mXuGNUb" fullword ascii
    $s15 = "function pGLJ(tjBxN) {" fullword ascii
    $s16 = "if (HSGQp > 153435-916){return true;} else {return false;}" fullword ascii
    $s17 = "function Italrnvn() {" fullword ascii
    $s18 = "return zVLr.responseBody;" fullword ascii
    $s19 = "function WAxbpwW(zVLr) {" fullword ascii
    $s20 = "return new ActiveXObject(cqcrmx);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}