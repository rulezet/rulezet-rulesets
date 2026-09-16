rule sig_20160315_0b05ab0ef311321d0cea37acb2e833bf {
  meta:
    description = "datamaliciousorder - file 20160315_0b05ab0ef311321d0cea37acb2e833bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff3a179a498edd64c55db99da84fa5d03126baff8eb582069fcbf58b43b1788f"

  strings:
    $s1  = "return KPAJTJb[0] + KPAJTJb[2] + KPAJTJb[4] + \".F\" + KPAJTJb[7] + KPAJTJb[9] + KPAJTJb[12] + KPAJTJb[14];" fullword ascii
    $s2  = "var vs = true  , fSRc = qqK[7] + qqK[9] + qqK[11];" fullword ascii
    $s3  = "GwFxT.open(CoFeX,lEYFt,false);" fullword ascii
    $s4  = "var KPAJTJb = KQDOc(\"Sc LcrjNBB r HqYnonAsg ipting uTadjBu DRA ile fVQhyYBSYAtuLt System JU BcUPm Obj fuhXru ect oSCpFrq arWyr" ascii
    $s5  = "var KPAJTJb = KQDOc(\"Sc LcrjNBB r HqYnonAsg ipting uTadjBu DRA ile fVQhyYBSYAtuLt System JU BcUPm Obj fuhXru ect oSCpFrq arWyr" ascii
    $s6  = "var qqK = (\"2.XMLHTTP BDSNjLI MMTVs XML ream St dnSLhNVN AD OpJgumS O STnG D\").split(\" \");" fullword ascii
    $s7  = "if (lDMYx > 189000-467){return true;} else {return false;}" fullword ascii
    $s8  = "function SsfLXqONW(ZRSdgIKPWPm) {" fullword ascii
    $s9  = "return CMBt.ExpandEnvironmentStrings(VcNNB);" fullword ascii
    $s10 = "function qoAAaVTH() {" fullword ascii
    $s11 = "function vClT(GwFxT,lEYFt,CoFeX) {" fullword ascii
    $s12 = "function DBvg(nyidp) {" fullword ascii
    $s13 = "function Sifk(lDMYx) {" fullword ascii
    $s14 = "function UcWkyuO(CMBt,VcNNB) {" fullword ascii
    $s15 = "function eQjvs(dsOAge) {" fullword ascii
    $s16 = "function qJrz(oefhX) {" fullword ascii
    $s17 = "function rhPyI(sZedcI) {" fullword ascii
    $s18 = "if(h>=l.length) {break;}" fullword ascii
    $s19 = "if (AvUJB == 328-128){return true;} else {return false;}" fullword ascii
    $s20 = "return UcWkyuO(cC,IkmGw[362-356]+IkmGw[118-111]+IkmGw[447-439]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}