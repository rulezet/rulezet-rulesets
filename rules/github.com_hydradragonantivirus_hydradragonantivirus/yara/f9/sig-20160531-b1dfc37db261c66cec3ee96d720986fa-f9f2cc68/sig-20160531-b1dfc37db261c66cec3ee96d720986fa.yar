rule sig_20160531_b1dfc37db261c66cec3ee96d720986fa {
  meta:
    description = "datamaliciousorder - file 20160531_b1dfc37db261c66cec3ee96d720986fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a73cb5df2d6ba20dc47c687cb1f8d12b318fde41105659589da53777fd3ba9a4"

  strings:
    $s1  = "var ErgsCF=function(){return WScript.CreateObject(MxGAGJTJBHFtcrd[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function SpJqfJKYQxsvoRPAjWF(wGPTgcrXIssVGpkHsva,IzkRATWiNgxxrv){return wGPTgcrXIssVGpkHsva.charAt(IzkRATWiNgxxrv);}" fullword ascii
    $s3  = "qDHRJQqVb=0;HPqDHRJQqVb<fhcKshKdYNeB.length;HPqDHRJQqVb++) {sxuFWHJC+=ajuohgoJEu[fhcKshKdYNeB[HPqDHRJQqVb]];}return sxuFWHJC.sub" ascii
    $s4  = "aa.length);return vBkDNxIJHmGjmlLB;}" fullword ascii
    $s5  = "(eHSIr,0x1,0x0)}function OyvSNAHnEVDhnd(dQDKDgrILMSp,BAqWzoCOiGBTW,UoKhSyPZe){var iwUPlao=dQDKDgrILMSp.createtextfile(BAqWzoCOiG" ascii
    $s6  = "function VaNTpbSZEJLSdtvoRk(OhFFKfB,BmDTbEBPNKSm,FNbQbkSG){return String.fromCharCode(OhFFKfB,BmDTbEBPNKSm,FNbQbkSG);}" fullword ascii
    $s7  = "function QPCrymH(){return zEmqwf(MxGAGJTJBHFtcrd[9],[1,5,7],MxGAGJTJBHFtcrd[10]);}" fullword ascii
    $s8  = "FzUn);else vBkDNxIJHmGjmlLB += VaNTpbSZEJLSdtvoRk(zkCLSAosTDJTDp, fdHPZXmwPzrFzUn, zSlIP);} while (RyeCoAWsHJKqRQX < ZwyAzwGXAsP" ascii
    $s9  = "function MmRksMBa(){return ErgsCF.ExpandEnvironmentStrings(QPCrymH())}" fullword ascii
    $s10 = "function ISThRVU(){return zEmqwf(MxGAGJTJBHFtcrd[11],[2,4,8,10],MxGAGJTJBHFtcrd[12]);}" fullword ascii
    $s11 = "var janadAw=function(){return new ActiveXObject(MxGAGJTJBHFtcrd[1]);}();" fullword ascii
    $s12 = "string(3,sxuFWHJC.length);}" fullword ascii
    $s13 = "function BNZdHh(){return zEmqwf(MxGAGJTJBHFtcrd[13],[0,3,6],MxGAGJTJBHFtcrd[14]);}" fullword ascii
    $s14 = "function kTxzzeumoGo(ZwyAzwGXAsPaa) {var mlFnjslFnUqk = XNtdhIzMXsi.join(MxGAGJTJBHFtcrd[7]);var zkCLSAosTDJTDp, fdHPZXmwPzrFzUn" ascii
    $s15 = "l == 64) vBkDNxIJHmGjmlLB += lc(zkCLSAosTDJTDp);else if (XYWpY == 64) vBkDNxIJHmGjmlLB += lxWUErWUdO(zkCLSAosTDJTDp, fdHPZXmwPzr" ascii
    $s16 = "function BAApBc(ZjgOnGvRaygqys,eHSIr) {var GpmHn=[MxGAGJTJBHFtcrd[15]];ZjgOnGvRaygqys[GpmHn[0]]" fullword ascii
    $s17 = "function lc(guxZpMpyB){return String.fromCharCode(guxZpMpyB);}" fullword ascii
    $s18 = "BTW,true);iwUPlao.WriteLine(UoKhSyPZe);iwUPlao.Close();}" fullword ascii
    $s19 = "(eHSIr,0x1,0x0)}function OyvSNAHnEVDhnd(dQDKDgrILMSp,BAqWzoCOiGBTW,UoKhSyPZe){var iwUPlao=dQDKDgrILMSp.createtextfile(BAqWzoCOiG" ascii
    $s20 = "function kTxzzeumoGo(ZwyAzwGXAsPaa) {var mlFnjslFnUqk = XNtdhIzMXsi.join(MxGAGJTJBHFtcrd[7]);var zkCLSAosTDJTDp, fdHPZXmwPzrFzUn" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}