rule sig_20160526_266966085017240994e54d66d1f55f76 {
  meta:
    description = "datamaliciousorder - file 20160526_266966085017240994e54d66d1f55f76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49c896bec2b073ce98632a9f7a4d930a3121ec395f6243b2cbd8d9491bc71cb8"

  strings:
    $s1  = "function hwnSBSwtDNB(KPMxpbADEcRJH) {var oFRvE = mzzsquleJkUamaikp.join(cujMuegxNDisxSDTcLV[0]);var OBlJtkWDkObfvLozW, dqLFZBIiu" ascii
    $s2  = "else if (zqkaUbpuXdJgAUQjuLSJUgI == (710 + Math.round((Math.pow(Math.sin(447), 2) + Math.pow(Math.cos(447), 2) - 1))-646)) VvdNY" ascii
    $s3  = "function IOUrdQKQTgVlvMDaCpHE(WsuVhK,llIaPQENsNhOSlyn){return WsuVhK.charAt(llIaPQENsNhOSlyn);}" fullword ascii
    $s4  = "function ysVnbIezzeedWxfdsSlJVoT(cTlMZdXBeftakDbzJ,BtlJDdiuIHArCOMwKSOr){return String.fromCharCode(cTlMZdXBeftakDbzJ,BtlJDdiuIH" ascii
    $s5  = "function ysVnbIezzeedWxfdsSlJVoT(cTlMZdXBeftakDbzJ,BtlJDdiuIHArCOMwKSOr){return String.fromCharCode(cTlMZdXBeftakDbzJ,BtlJDdiuIH" ascii
    $s6  = "function hwnSBSwtDNB(KPMxpbADEcRJH) {var oFRvE = mzzsquleJkUamaikp.join(cujMuegxNDisxSDTcLV[0]);var OBlJtkWDkObfvLozW, dqLFZBIiu" ascii
    $s7  = "function PvfzdgkdQfKqzIuA(HyxSIjHjnYqnTd,WsvyDVyBkYYDynmNqm,RUzomDGcOOiUCgLGiWWcwOfl){return String.fromCharCode(HyxSIjHjnYqnTd," ascii
    $s8  = "function O(CLGZzjfHjl){return String.fromCharCode(CLGZzjfHjl);}" fullword ascii
    $s9  = "function PvfzdgkdQfKqzIuA(HyxSIjHjnYqnTd,WsvyDVyBkYYDynmNqm,RUzomDGcOOiUCgLGiWWcwOfl){return String.fromCharCode(HyxSIjHjnYqnTd," ascii
    $s10 = "function xOMiU(DBDoLhpHDBowFtKLzpVn,bEXSpEBXKuBDkgaaFH){return DBDoLhpHDBowFtKLzpVn.indexOf(bEXSpEBXKuBDkgaaFH);}" fullword ascii
    $s11 = "mhYEpGOsrpoNi += ysVnbIezzeedWxfdsSlJVoT(OBlJtkWDkObfvLozW, dqLFZBIiuICA);else VvdNYmhYEpGOsrpoNi += PvfzdgkdQfKqzIuA(OBlJtkWDkO" ascii
    $s12 = "bfvLozW, dqLFZBIiuICA, bvtqZRDvKbZMi);} while (QrczimyVrxzNnc < KPMxpbADEcRJH.length);return VvdNYmhYEpGOsrpoNi;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}