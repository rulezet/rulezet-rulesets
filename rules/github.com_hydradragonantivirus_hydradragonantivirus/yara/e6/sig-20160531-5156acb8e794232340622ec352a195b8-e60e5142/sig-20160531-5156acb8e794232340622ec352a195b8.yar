rule sig_20160531_5156acb8e794232340622ec352a195b8 {
  meta:
    description = "datamaliciousorder - file 20160531_5156acb8e794232340622ec352a195b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edc3eab23ee195ceabeaaf3659f425d2aa2d1bcb38e2b24da6278f7a466f3417"

  strings:
    $s1  = "var CIhkPqPKx=function(){return WScript.CreateObject(IGUHsIIffBnJ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function wPiuXWnnKQvnUybkUJEyH(neEeBGqRDOHBHFiRwSpqZTpP,AAPCQMercAhAtPEeYp){return neEeBGqRDOHBHFiRwSpqZTpP.charAt(AAPCQMercAhAt" ascii
    $s3  = "function wPiuXWnnKQvnUybkUJEyH(neEeBGqRDOHBHFiRwSpqZTpP,AAPCQMercAhAtPEeYp){return neEeBGqRDOHBHFiRwSpqZTpP.charAt(AAPCQMercAhAt" ascii
    $s4  = "function sMhFqQjFUooFhL(){return vsJcWnLnQZQ(IGUHsIIffBnJ[13],[0,3,6],IGUHsIIffBnJ[14]);}" fullword ascii
    $s5  = "function mlEEkuwKHbchPREhlZKeedl(ctSNxWTpgZMIUiSlUPWmE,XmTVWMrcKjYJGJKlgZSFgp,eoalLKUMFWNhBkZGpGyKzlM){return String.fromCharCod" ascii
    $s6  = "function vsJcWnLnQZQ(RmPRv,Bhhbcow,EpaIrpb){yaqhGYxPn=RmPRv.split(EpaIrpb);ktavaW = IGUHsIIffBnJ[0];for(LbPxTH=0;LbPxTH<Bhhbcow." ascii
    $s7  = "function BPjOBgmv(){return CIhkPqPKx.ExpandEnvironmentStrings(DijYRQ())}" fullword ascii
    $s8  = "length;LbPxTH++) {ktavaW+=yaqhGYxPn[Bhhbcow[LbPxTH]];}return ktavaW.substring(3,ktavaW.length);}" fullword ascii
    $s9  = "ezaoJLhNSXYlxOL, qEQTLJgCMtkm);} while (SfJmObuGRcrrFnimBNomYjr < UKsUJUPOcDgTU.length);return jGiEeJYRjcROxl;}" fullword ascii
    $s10 = "var Udmce=function(){return new ActiveXObject(IGUHsIIffBnJ[1]);}();" fullword ascii
    $s11 = "function mlEEkuwKHbchPREhlZKeedl(ctSNxWTpgZMIUiSlUPWmE,XmTVWMrcKjYJGJKlgZSFgp,eoalLKUMFWNhBkZGpGyKzlM){return String.fromCharCod" ascii
    $s12 = "function emNwMCUrFwgHOZrRSoen(AhmiYnZjft,oJMZSijboAtaqbmS){return AhmiYnZjft.indexOf(oJMZSijboAtaqbmS);}" fullword ascii
    $s13 = "& 0xff;qEQTLJgCMtkm = CxrCWOhzVAMc & 0xff;if (VfJZOzhfO == 64) jGiEeJYRjcROxl += wF(pxWDfFwWSEb);else if (whNtOiINJWRtR == 64) j" ascii
    $s14 = "function ljggpyomBCWkW(){return vsJcWnLnQZQ(IGUHsIIffBnJ[11],[2,4,8,10],IGUHsIIffBnJ[12]);}" fullword ascii
    $s15 = "function wFrTwDKKdUf(TLlOmsevC,RhdOXzhGdJD) {var QGsZASiobPvJv=[IGUHsIIffBnJ[15]];TLlOmsevC[QGsZASiobPvJv[0]]" fullword ascii
    $s16 = "function CWqzxwJXu(UKsUJUPOcDgTU) {var btTtytD = FnzbyAJFBeLbUXjSEwHjD.join(IGUHsIIffBnJ[7]);var pxWDfFwWSEb, ezaoJLhNSXYlxOL, q" ascii
    $s17 = "function vsJcWnLnQZQ(RmPRv,Bhhbcow,EpaIrpb){yaqhGYxPn=RmPRv.split(EpaIrpb);ktavaW = IGUHsIIffBnJ[0];for(LbPxTH=0;LbPxTH<Bhhbcow." ascii
    $s18 = "function wLFUlOfqHSKwcOrYowBy(fbYpyLaRqIlJaMVDDcRcHq,dTTeWa){return String.fromCharCode(fbYpyLaRqIlJaMVDDcRcHq,dTTeWa);}" fullword ascii
    $s19 = "function DijYRQ(){return vsJcWnLnQZQ(IGUHsIIffBnJ[9],[1,5,7],IGUHsIIffBnJ[10]);}" fullword ascii
    $s20 = "GiEeJYRjcROxl += wLFUlOfqHSKwcOrYowBy(pxWDfFwWSEb, ezaoJLhNSXYlxOL);else jGiEeJYRjcROxl += mlEEkuwKHbchPREhlZKeedl(pxWDfFwWSEb, " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}