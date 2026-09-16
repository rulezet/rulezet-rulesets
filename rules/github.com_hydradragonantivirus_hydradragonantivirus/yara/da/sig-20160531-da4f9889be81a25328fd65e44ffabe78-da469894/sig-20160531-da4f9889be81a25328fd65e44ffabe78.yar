rule sig_20160531_da4f9889be81a25328fd65e44ffabe78 {
  meta:
    description = "datamaliciousorder - file 20160531_da4f9889be81a25328fd65e44ffabe78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b431b4154285d0f83297b358340cc0640702b2d1fa497762e37469ebaa3463c"

  strings:
    $s1  = "var HeKMLOsi=function(){return WScript.CreateObject(QNkHhjKkZWlaQ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WoMJKlc(CBCeMAKaAwPPnIepSdD,jhWXqWK){return CBCeMAKaAwPPnIepSdD.charAt(jhWXqWK);}" fullword ascii
    $s3  = "UmQlRjtwLJe.length);return oHWBVrGoxil;}" fullword ascii
    $s4  = "function ZCCwXrIfLihs(WBuyC,vArOYGF) {var BxUUUUsSy=[QNkHhjKkZWlaQ[15]];WBuyC[BxUUUUsSy[0]]" fullword ascii
    $s5  = "function JRfvIVJVFYjRwrJMvzI(FlarEuPRrkTsMhSh,EWUTdRofkamIVCsMurBSms){return String.fromCharCode(FlarEuPRrkTsMhSh,EWUTdRofkamIVC" ascii
    $s6  = "function EwwrUUxQJLxsWylyTfpzKAf(GanfEOhERJhomncQyGvk,lqtTDp,CGbBclnOyYhVjwtBahwOuO){return String.fromCharCode(GanfEOhERJhomncQ" ascii
    $s7  = "function zvnrEm(){return HeKMLOsi.ExpandEnvironmentStrings(ATnKPTTLk())}" fullword ascii
    $s8  = "function EpREoogLvoIIpJIGT(fDBjdRHURKa,rKTNbcpKl){return fDBjdRHURKa.indexOf(rKTNbcpKl);}" fullword ascii
    $s9  = "var iwlLpaNGRy=function(){return new ActiveXObject(QNkHhjKkZWlaQ[1]);}();" fullword ascii
    $s10 = "function lNNMMsueFY(){return bodcuxwliGHwl(QNkHhjKkZWlaQ[11],[2,4,8,10],QNkHhjKkZWlaQ[12]);}" fullword ascii
    $s11 = "se if (QTkHjcncNBztmqsPU == 64) oHWBVrGoxil += JRfvIVJVFYjRwrJMvzI(sHyzpAOpEQdDhdqOBhxOqQ, eOQcmEcqwGOfRQFaOvmy);else oHWBVrGoxi" ascii
    $s12 = "g=0;ffhmtjahMYCug<jirmVgvydrF.length;ffhmtjahMYCug++) {xsyAzI+=VOrxqHBxhNQgaZ[jirmVgvydrF[ffhmtjahMYCug]];}return xsyAzI.substri" ascii
    $s13 = "(vArOYGF,0x1,0x0)}function AICeFOOCU(LjgXbLBGgK,ndCeOMDkfDJ,nULaOgN){var DSwrgRKJK=LjgXbLBGgK.createtextfile(ndCeOMDkfDJ,true);D" ascii
    $s14 = "function bodcuxwliGHwl(IgHftj,jirmVgvydrF,nvjAQE){VOrxqHBxhNQgaZ=IgHftj.split(nvjAQE);xsyAzI = QNkHhjKkZWlaQ[0];for(ffhmtjahMYCu" ascii
    $s15 = "function nCGwt(kmUmQlRjtwLJe) {var IxHfkaxrTVVcb = BjyGkVxKUpTFF.join(QNkHhjKkZWlaQ[7]);var sHyzpAOpEQdDhdqOBhxOqQ, eOQcmEcqwGOf" ascii
    $s16 = "function nCGwt(kmUmQlRjtwLJe) {var IxHfkaxrTVVcb = BjyGkVxKUpTFF.join(QNkHhjKkZWlaQ[7]);var sHyzpAOpEQdDhdqOBhxOqQ, eOQcmEcqwGOf" ascii
    $s17 = "function bodcuxwliGHwl(IgHftj,jirmVgvydrF,nvjAQE){VOrxqHBxhNQgaZ=IgHftj.split(nvjAQE);xsyAzI = QNkHhjKkZWlaQ[0];for(ffhmtjahMYCu" ascii
    $s18 = "function ATnKPTTLk(){return bodcuxwliGHwl(QNkHhjKkZWlaQ[9],[1,5,7],QNkHhjKkZWlaQ[10]);}" fullword ascii
    $s19 = "l += EwwrUUxQJLxsWylyTfpzKAf(sHyzpAOpEQdDhdqOBhxOqQ, eOQcmEcqwGOfRQFaOvmy, jlNwfCPxUoZgDk);} while (gwrEDmoKKrPvbEOVMHjWmJw < km" ascii
    $s20 = "function Yk(anoPBaTAgOviSJedQwZWt){return String.fromCharCode(anoPBaTAgOviSJedQwZWt);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}