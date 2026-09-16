rule sig_20160314_1aee8d5df96a85232bcb3893ab7c63df {
  meta:
    description = "datamaliciousorder - file 20160314_1aee8d5df96a85232bcb3893ab7c63df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6385dc3048969cebe2483230229132699c7c2505a1ee6d473476e5521ad5b72"

  strings:
    $s1  = "return zTpHjFd[0] + zTpHjFd[2] + zTpHjFd[4] + \".F\" + zTpHjFd[7] + zTpHjFd[9] + zTpHjFd[12] + zTpHjFd[14];" fullword ascii
    $s2  = "var jE = true  , ALpf = IEV[7] + IEV[9] + IEV[11];" fullword ascii
    $s3  = "var IEV = (\"2.XMLHTTP SudiUgC yOYvF XML ream St tPEVPevq AD WJoCrsq O qoxp D\").split(\" \");" fullword ascii
    $s4  = "VpPuH.open(szxBA,irxnB,false);" fullword ascii
    $s5  = "var zTpHjFd = \"Sc zBYHbSK r bqntFySio ipting tNQKtmb Ryn ile AqJEfCuJVAAEgh System kL ihPmM Obj efqVes ect wtoYcRM Nszfv\".spli" ascii
    $s6  = "var zTpHjFd = \"Sc zBYHbSK r bqntFySio ipting tNQKtmb Ryn ile AqJEfCuJVAAEgh System kL ihPmM Obj efqVes ect wtoYcRM Nszfv\".spli" ascii
    $s7  = "return tqSf.responseBody;" fullword ascii
    $s8  = "function tIod(cIOXv) {" fullword ascii
    $s9  = "function atkH(GdysY) {" fullword ascii
    $s10 = "function IzNM(CkMSq) {" fullword ascii
    $s11 = "if(i>=x.length) {break;}" fullword ascii
    $s12 = "IzNM(eYu); eYu.type = 1; AWKv(eYu,ZuzibRI(nW)); if (Lown(duieRWlw(eYu)))  {" fullword ascii
    $s13 = "return nITIhr.position=935-935;" fullword ascii
    $s14 = "return new ActiveXObject(VhUktN);" fullword ascii
    $s15 = "return WxZ.size;" fullword ascii
    $s16 = "function Jhvjg(VhUktN) {" fullword ascii
    $s17 = "return YZeC.ExpandEnvironmentStrings(VsEno);" fullword ascii
    $s18 = "function AWKv(HfbrM,FOxeJ) {" fullword ascii
    $s19 = "function Lown(cfBmj) {" fullword ascii
    $s20 = "function quHL(OkoTs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}