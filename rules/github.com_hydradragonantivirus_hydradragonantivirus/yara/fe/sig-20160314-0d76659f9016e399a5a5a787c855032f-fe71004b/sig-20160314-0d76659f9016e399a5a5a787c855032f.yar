rule sig_20160314_0d76659f9016e399a5a5a787c855032f {
  meta:
    description = "datamaliciousorder - file 20160314_0d76659f9016e399a5a5a787c855032f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1daa8d1daa0f6c39203a99f87c6b1f64542c483870165f65e8ba186d81e920a"

  strings:
    $s1  = "return TcGnEOF[0] + TcGnEOF[2] + TcGnEOF[4] + \".F\" + TcGnEOF[7] + TcGnEOF[9] + TcGnEOF[12] + TcGnEOF[14];" fullword ascii
    $s2  = "var oX = true  , mIHi = Jsp[7] + Jsp[9] + Jsp[11];" fullword ascii
    $s3  = "var TcGnEOF = \"Sc FbcMZIr r kcooCtjXm ipting ocewMbm FmD ile ouRbOoLtUuDbjQ System Yc YZfMK Obj xicWkE ect FvCwPLn vVhXu\".spli" ascii
    $s4  = "var TcGnEOF = \"Sc FbcMZIr r kcooCtjXm ipting ocewMbm FmD ile ouRbOoLtUuDbjQ System Yc YZfMK Obj xicWkE ect FvCwPLn vVhXu\".spli" ascii
    $s5  = "var Jsp = (\"2.XMLHTTP CYMpGvM neoJb XML ream St ryUcxzmW AD kvYmJcN O mIiy D\").split(\" \");" fullword ascii
    $s6  = "bHdLs.open(GAkwx,dYLmR,false);" fullword ascii
    $s7  = "if (Pbxpr > 157151-593){return true;} else {return false;}" fullword ascii
    $s8  = "function VHigk(SutmoA) {" fullword ascii
    $s9  = "function EaaF(hQWHx,mvhlA) {" fullword ascii
    $s10 = "return eyxT.responseBody;" fullword ascii
    $s11 = "function ADVq(gvQWI) {" fullword ascii
    $s12 = "return new ActiveXObject(tstIkE);" fullword ascii
    $s13 = "if(w>=l.length) {break;}" fullword ascii
    $s14 = "XkE = w; break; " fullword ascii
    $s15 = "return rbYzmkH(zl,oHYnk[967-961]+oHYnk[122-115]+oHYnk[765-757]);" fullword ascii
    $s16 = "function hGQD(hsbcC) {" fullword ascii
    $s17 = "return SutmoA.position=722-722;" fullword ascii
    $s18 = "return kDIO.ExpandEnvironmentStrings(bwnvl);" fullword ascii
    $s19 = "if (L >= hsbcC.length) {break;}" fullword ascii
    $s20 = "function zTNN(TDOGQ,JulKm) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}