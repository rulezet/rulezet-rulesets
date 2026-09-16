rule sig_20160311_81b0f80949e07071ef7b894eff578f6b {
  meta:
    description = "datamaliciousorder - file 20160311_81b0f80949e07071ef7b894eff578f6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10fd9ea5e93fabbce1626a00fa55f12df503a172979bed83bfd0f988d54a3c32"

  strings:
    $s1  = "var Gi = true  , amik = foa[7] + foa[9] + foa[11];" fullword ascii
    $s2  = "return ICiiePP[0] + ICiiePP[2] + ICiiePP[4] + \".F\" + ICiiePP[7] + ICiiePP[9] + ICiiePP[12] + ICiiePP[14];" fullword ascii
    $s3  = "var foa = (\"2.XMLHTTP GPctpgO sKOEp XML ream St BgPQKAsA AD OQBvIVF O CbTl D\").split(\" \");" fullword ascii
    $s4  = "MokbM.open(oiTAg,FLBwy,false);" fullword ascii
    $s5  = "var ICiiePP = \"Sc PpowQbL r LYHaovJgP ipting QfwRMdu Kcr ile DIqqDZXJnTBQDL System YX rVAZQ Obj zDkNTV ect KdgcPXF\".split(\" " ascii
    $s6  = "function LwrX(vdByb) {" fullword ascii
    $s7  = "function UfXT(KhCTC) {" fullword ascii
    $s8  = "return new ActiveXObject(DvSvbo);" fullword ascii
    $s9  = "return PQOOMr.position=944-944;" fullword ascii
    $s10 = "function CPJq(xRoVy) {" fullword ascii
    $s11 = "if (O >= QdimY.length) {break;}" fullword ascii
    $s12 = "return osmyZYl(Nq,foRfx[781-775]+foRfx[427-420]+foRfx[531-523]);" fullword ascii
    $s13 = "function sRlF(wKVEy) {" fullword ascii
    $s14 = "function ISJW(wkNWW) {" fullword ascii
    $s15 = "function WlWMqrcqT(IFuVZEIdPWF) {" fullword ascii
    $s16 = "return fJQN.responseBody;" fullword ascii
    $s17 = "if(k>=v.length) {break;}" fullword ascii
    $s18 = "return yHhIw;" fullword ascii
    $s19 = "function OoQUv(PQOOMr) {" fullword ascii
    $s20 = "function Hixa(QdimY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}