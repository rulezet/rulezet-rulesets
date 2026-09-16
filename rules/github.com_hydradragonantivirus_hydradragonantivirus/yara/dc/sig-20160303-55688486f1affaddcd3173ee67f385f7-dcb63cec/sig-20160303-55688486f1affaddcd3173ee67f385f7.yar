rule sig_20160303_55688486f1affaddcd3173ee67f385f7 {
  meta:
    description = "datamaliciousorder - file 20160303_55688486f1affaddcd3173ee67f385f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81e7a34347ab66d9ed106522f5b5c7316fbddf2d3485aca11ac3b6240b824644"

  strings:
    $s1  = "var MwChN = \"txUfVu VYM pt.Shell NZYYOnz Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var XV = true  , sOxt = ETp[7] + \"\" + ETp[9];" fullword ascii
    $s3  = "return hvtjLsf[0] + hvtjLsf[2] + hvtjLsf[4] + \".F\" + hvtjLsf[7] + hvtjLsf[9] + hvtjLsf[12] + hvtjLsf[14];" fullword ascii
    $s4  = "var ETp = (SUA + \"TTP\" + \" qgVUHFQ lzfUg XML ream St wPvnVYvX AD TtceqDJ OD\").split(\" \");" fullword ascii
    $s5  = "cvkiH.open(cuGEa,zztiz,false);" fullword ascii
    $s6  = "var hvtjLsf = \"Sc sVEKhBp r qFwcRoTVU ipting unTCTSG SXz ile DnUZSdQsHuVXiN System Ss GImuU Obj qqTWce ect wEtfvfp\".split(\" " ascii
    $s7  = "if(z>=E.length) {break;}" fullword ascii
    $s8  = "function LOol(cvkiH,zztiz,cuGEa) {" fullword ascii
    $s9  = "function WkSd(KaPEL) {" fullword ascii
    $s10 = "return Cz.ExpandEnvironmentStrings(MwChN[6]);" fullword ascii
    $s11 = "function ZJqzsiwrL(bhPfa,mWteD,GtMmn) {" fullword ascii
    $s12 = "return iqqyi;" fullword ascii
    $s13 = "function UXKi(xOiGF,MlVtn) {" fullword ascii
    $s14 = "function DZTl(ZxOid) {" fullword ascii
    $s15 = "if (rAyNb == 792-592){return true;} else {return false;}" fullword ascii
    $s16 = "function IFjI(lsFYJ) {" fullword ascii
    $s17 = "if (((new Date())>0,7395972888)) {" fullword ascii
    $s18 = "function zDyc(EctfT) {" fullword ascii
    $s19 = "function qCwaTfEr() {" fullword ascii
    $s20 = "function pwQfYkp(pTXt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}