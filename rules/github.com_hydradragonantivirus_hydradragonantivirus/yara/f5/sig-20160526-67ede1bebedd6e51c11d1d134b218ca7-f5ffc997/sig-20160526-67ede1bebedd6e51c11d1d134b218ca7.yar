rule sig_20160526_67ede1bebedd6e51c11d1d134b218ca7 {
  meta:
    description = "datamaliciousorder - file 20160526_67ede1bebedd6e51c11d1d134b218ca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1aa0320b59d2d76c4c970c7b7b5ea2e8b688f7c3104d3eb3c59b3e5c9a91df85"

  strings:
    $s1  = "function oNmpULz(DCEdnWKVfYcce) {var ORfyhKYfB = inYrL.join(TXVgAIpW[0]);var VallTJpoZZNNZd, GagEZnOTQxASS, xJiHwZpxzrCYqorF, oS" ascii
    $s2  = "YnE += ce(VallTJpoZZNNZd);else if (alnKfUBVQlDS == (476 + Math.round((Math.pow(Math.sin(455), 2) + Math.pow(Math.cos(455), 2) - " ascii
    $s3  = "function BInHwrxolYSqFZcLVXs(HdjKFlaFVhQxkzvjcegZJmyG,pDplkoPuzTylDNAoPBHsK){return HdjKFlaFVhQxkzvjcegZJmyG.charAt(pDplkoPuzTyl" ascii
    $s4  = "function BInHwrxolYSqFZcLVXs(HdjKFlaFVhQxkzvjcegZJmyG,pDplkoPuzTylDNAoPBHsK){return HdjKFlaFVhQxkzvjcegZJmyG.charAt(pDplkoPuzTyl" ascii
    $s5  = "function nMMzvqdIldeY(SFsCkMDZ,PoPPeiiMMTQhNEkZilYbZdWr){return String.fromCharCode(SFsCkMDZ,PoPPeiiMMTQhNEkZilYbZdWr);}" fullword ascii
    $s6  = "function wCExmJssFqiagnzMZFYBBNf(YrNpKL,EIccfYygonCuZfheiIUWNss,xLUbwwCOWpgSQ){return String.fromCharCode(YrNpKL,EIccfYygonCuZfh" ascii
    $s7  = "allTJpoZZNNZd, GagEZnOTQxASS, xJiHwZpxzrCYqorF);} while (iNSjucdEJkpoNPgPlPMpx < DCEdnWKVfYcce.length);return TgtMwOtgCSbrUmCYnE" ascii
    $s8  = "1))-412)) TgtMwOtgCSbrUmCYnE += nMMzvqdIldeY(VallTJpoZZNNZd, GagEZnOTQxASS);else TgtMwOtgCSbrUmCYnE += wCExmJssFqiagnzMZFYBBNf(V" ascii
    $s9  = "function wCExmJssFqiagnzMZFYBBNf(YrNpKL,EIccfYygonCuZfheiIUWNss,xLUbwwCOWpgSQ){return String.fromCharCode(YrNpKL,EIccfYygonCuZfh" ascii
    $s10 = "function ce(TtcYPcTIyjDuhD){return String.fromCharCode(TtcYPcTIyjDuhD);}" fullword ascii
    $s11 = "function oNmpULz(DCEdnWKVfYcce) {var ORfyhKYfB = inYrL.join(TXVgAIpW[0]);var VallTJpoZZNNZd, GagEZnOTQxASS, xJiHwZpxzrCYqorF, oS" ascii
    $s12 = "function LVldxmRcLbiApb(nKZyIkU,SZZIHDkWePMTSsHc){return nKZyIkU.indexOf(SZZIHDkWePMTSsHc);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}