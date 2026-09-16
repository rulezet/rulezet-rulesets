rule sig_20160531_3d6cd59cdab62bebd86fb683fef57f60 {
  meta:
    description = "datamaliciousorder - file 20160531_3d6cd59cdab62bebd86fb683fef57f60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94909956d4ec0d803f6bc6998bec198d479543fb2156957058c4821f0683f49c"

  strings:
    $s1  = "var wKaXyWDqwsSnee=function(){return WScript.CreateObject(HGOYZmMCSHn[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function vHkmIEpyEQsDqYARdcUAJRy(OyyNeWotPcoqZfSUjV,RCPxZqfoUCqLmZtEuxPM){return OyyNeWotPcoqZfSUjV.charAt(RCPxZqfoUCqLmZtEuxPM)" ascii
    $s3  = "function vHkmIEpyEQsDqYARdcUAJRy(OyyNeWotPcoqZfSUjV,RCPxZqfoUCqLmZtEuxPM){return OyyNeWotPcoqZfSUjV.charAt(RCPxZqfoUCqLmZtEuxPM)" ascii
    $s4  = "function CyXmgfjPmk(BUVzvO,VIiDafUQPuNLZrYFvJyOzs){return BUVzvO.indexOf(VIiDafUQPuNLZrYFvJyOzs);}" fullword ascii
    $s5  = "(XQLHoDtK,0x1,0x0)}function eYYvlr(dHvSMcZKcOjS,UPotXCBNphS,KAaOnHgsVA){var YKXImykwhRPK=dHvSMcZKcOjS.createtextfile(UPotXCBNphS" ascii
    $s6  = "(tCXjeRv=0;tCXjeRv<aWINErBEmdareC.length;tCXjeRv++) {CCIRTcB+=xCunHHAhRqQjbF[aWINErBEmdareC[tCXjeRv]];}return CCIRTcB.substring(" ascii
    $s7  = "function PgFAkKUJ(hdQFePFLdODK,kNLxfsFwPRpJNPRkKyWmPHSz,EMjIbTsfWwhZCONqjOqyoy){return String.fromCharCode(hdQFePFLdODK,kNLxfsFw" ascii
    $s8  = "function rcUGFawu(){return IlugRuKRZG(HGOYZmMCSHn[9],[1,5,7],HGOYZmMCSHn[10]);}" fullword ascii
    $s9  = "function gn(wMPGPveEdkbSeRY){return String.fromCharCode(wMPGPveEdkbSeRY);}" fullword ascii
    $s10 = "function sWXfZKYVAOXbxy(LKjIHRXofXpZt) {var iNlFXIgsSETFAtoYyhbJSdg = flHQjXsNmHqADBhWndQ.join(HGOYZmMCSHn[7]);var PUgoVHFpLjxFy" ascii
    $s11 = "function INPpUjHVhaFMsP(){return wKaXyWDqwsSnee.ExpandEnvironmentStrings(rcUGFawu())}" fullword ascii
    $s12 = " += PgFAkKUJ(PUgoVHFpLjxFymzwHJAc, zpUWqNLE, xcpaMNJYyDsITCYVpJitMir);} while (YDVFXVJoQgfWGQFvkOJMhJ < LKjIHRXofXpZt.length);re" ascii
    $s13 = "function JrnnOc(rksREgelQMARvvQZu,zKIedrYASqptXgxfEgf){return String.fromCharCode(rksREgelQMARvvQZu,zKIedrYASqptXgxfEgf);}" fullword ascii
    $s14 = "(XQLHoDtK,0x1,0x0)}function eYYvlr(dHvSMcZKcOjS,UPotXCBNphS,KAaOnHgsVA){var YKXImykwhRPK=dHvSMcZKcOjS.createtextfile(UPotXCBNphS" ascii
    $s15 = "function sxLULt(yJlVjszC,XQLHoDtK) {var ZEeaebX=[HGOYZmMCSHn[15]];yJlVjszC[ZEeaebX[0]]" fullword ascii
    $s16 = ",true);YKXImykwhRPK.WriteLine(KAaOnHgsVA);YKXImykwhRPK.Close();}" fullword ascii
    $s17 = "function IlugRuKRZG(ThzkFgMqrZn,aWINErBEmdareC,ngaomQmm){xCunHHAhRqQjbF=ThzkFgMqrZn.split(ngaomQmm);CCIRTcB = HGOYZmMCSHn[0];for" ascii
    $s18 = "wHJAc);else if (jgYncuUPFJqSctMvkuWYxM == 64) EqAJsPfgeXDdaWQmD += JrnnOc(PUgoVHFpLjxFymzwHJAc, zpUWqNLE);else EqAJsPfgeXDdaWQmD" ascii
    $s19 = "function yTWaNNBnXfjn(){return IlugRuKRZG(HGOYZmMCSHn[13],[0,3,6],HGOYZmMCSHn[14]);}" fullword ascii
    $s20 = "function IlugRuKRZG(ThzkFgMqrZn,aWINErBEmdareC,ngaomQmm){xCunHHAhRqQjbF=ThzkFgMqrZn.split(ngaomQmm);CCIRTcB = HGOYZmMCSHn[0];for" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}