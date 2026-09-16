rule sig_20160404_777071876a9da9d98ba12846d21272fb {
  meta:
    description = "datamaliciousorder - file 20160404_777071876a9da9d98ba12846d21272fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c41ac1bb77a5885129487c97c6274351cb178b83b6dfaa3d3261b6e83d1ab784"

  strings:
    $s1  = "function bvQlEYEjk(WeOpgmxCqWJ) {" fullword ascii
    $s2  = "var MM = true  , DjGz = qzt[7] + qzt[9] + qzt[11];" fullword ascii
    $s3  = "return viLzMaD[0] + viLzMaD[2] + viLzMaD[4] + \".F\" + viLzMaD[7] + viLzMaD[9] + viLzMaD[12] + viLzMaD[14];" fullword ascii
    $s4  = "var viLzMaD = jJyds(dPmEarpMgr+\" \"+\"System PD xiMfw Obj STEIaf ect pRBZhmr wcHMz\", \" \");" fullword ascii
    $s5  = "var qzt = (\"2.XMLHTTP nGvRBRj KcoiZ XML ream St bVdjWpfv AD oAnGreJ O MNzk D\").split(\" \");" fullword ascii
    $s6  = "lRRc.open(kJrXr,iuhrA,false);" fullword ascii
    $s7  = "function rOQC(osEra) {" fullword ascii
    $s8  = "function OwIF(Rzewa) {" fullword ascii
    $s9  = "function GUSM(VgQzM,fhMjQ) {" fullword ascii
    $s10 = "return MtQJE;" fullword ascii
    $s11 = "function mvzpOgSA(XlSz) {" fullword ascii
    $s12 = "return new ActiveXObject(eiaF);" fullword ascii
    $s13 = "return \"apCSrwEevpkZsb\";" fullword ascii
    $s14 = "return MMk.split(BPsPf);" fullword ascii
    $s15 = "if (pCjFE > 159061-613){return true;} else {return false;}" fullword ascii
    $s16 = "RTT = H; break; " fullword ascii
    $s17 = "function nKAoV(kjYgjVhp,GNzW) {" fullword ascii
    $s18 = "return etfyn.status;" fullword ascii
    $s19 = "return RSQCUOl;" fullword ascii
    $s20 = "function HSFS(fIFEz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}