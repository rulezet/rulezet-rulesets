rule sig_20160531_47ba4e888669baa63dccfb7f39b84954 {
  meta:
    description = "datamaliciousorder - file 20160531_47ba4e888669baa63dccfb7f39b84954.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04dfada9e701fbc57d83fb83feac46e9a5a2d68d861a9b7c368c080520d0fd05"

  strings:
    $s1  = "var TQhDqUcCmclkqF=function(){return WScript.CreateObject(cpmlilN[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function kCunnkBXM(nCjrCNo,tZcnxPZQhXZEvznbktYz){return nCjrCNo.charAt(tZcnxPZQhXZEvznbktYz);}" fullword ascii
    $s3  = "YRZL=0;DJcKPYRZL<HQNiSOY.length;DJcKPYRZL++) {fyUXipNh+=pUWGmRXmuS[HQNiSOY[DJcKPYRZL]];}return fyUXipNh.substring(3,fyUXipNh.len" ascii
    $s4  = "function ddmSzTzl(eiyrKtMPFXVBG) {var uawOyyMdUxmDNAydPlstGYx = fHNDDG.join(cpmlilN[7]);var JZfTZvwpusrdHZtighh, ohhdHJERhBjld, " ascii
    $s5  = " ohhdHJERhBjld, EsZGedDjrPELZisNgAx);} while (QrmaV < eiyrKtMPFXVBG.length);return WAqwOOrBKuRTgOvh;}" fullword ascii
    $s6  = "function mcQxcEmRnnaAoNXyfNZeeInt(bbUUV,pMNUmquVpk,DzVbUFMPyqIRqKiyyXS){return String.fromCharCode(bbUUV,pMNUmquVpk,DzVbUFMPyqIR" ascii
    $s7  = "KocujsTTIxqmSRFlxedNX(JZfTZvwpusrdHZtighh, ohhdHJERhBjld);else WAqwOOrBKuRTgOvh += mcQxcEmRnnaAoNXyfNZeeInt(JZfTZvwpusrdHZtighh," ascii
    $s8  = "function kgHXfINq(){return TQhDqUcCmclkqF.ExpandEnvironmentStrings(xLPtYH())}" fullword ascii
    $s9  = "(gkyFb,0x1,0x0)}function mGNNafWns(RBTnBkAjRxZGMT,ATNteqFgaW,LDSDThivxXNcl){var nCvTS=RBTnBkAjRxZGMT.createtextfile(ATNteqFgaW,t" ascii
    $s10 = "function fOmmhhMp(aHolWAhfWTiIkl,HQNiSOY,QSHQrGMouv){pUWGmRXmuS=aHolWAhfWTiIkl.split(QSHQrGMouv);fyUXipNh = cpmlilN[0];for(DJcKP" ascii
    $s11 = "(gkyFb,0x1,0x0)}function mGNNafWns(RBTnBkAjRxZGMT,ATNteqFgaW,LDSDThivxXNcl){var nCvTS=RBTnBkAjRxZGMT.createtextfile(ATNteqFgaW,t" ascii
    $s12 = "function WS(tRCWGncUZhbJZiTX){return String.fromCharCode(tRCWGncUZhbJZiTX);}" fullword ascii
    $s13 = "function mcQxcEmRnnaAoNXyfNZeeInt(bbUUV,pMNUmquVpk,DzVbUFMPyqIRqKiyyXS){return String.fromCharCode(bbUUV,pMNUmquVpk,DzVbUFMPyqIR" ascii
    $s14 = "var mflWaIzQBUCB=function(){return new ActiveXObject(cpmlilN[1]);}();" fullword ascii
    $s15 = "function YsxfWopmJ(){return fOmmhhMp(cpmlilN[11],[2,4,8,10],cpmlilN[12]);}" fullword ascii
    $s16 = "function xLPtYH(){return fOmmhhMp(cpmlilN[9],[1,5,7],cpmlilN[10]);}" fullword ascii
    $s17 = "function wkIvibmsSvTapnhCn(rJSsEEImDGMzIUeJkmLgRQOk,TiELghoZd){return rJSsEEImDGMzIUeJkmLgRQOk.indexOf(TiELghoZd);}" fullword ascii
    $s18 = "function vTAyzAzmFE(yCDuzYivKXlp,gkyFb) {var CYQIFDauqeGY=[cpmlilN[15]];yCDuzYivKXlp[CYQIFDauqeGY[0]]" fullword ascii
    $s19 = "function fOmmhhMp(aHolWAhfWTiIkl,HQNiSOY,QSHQrGMouv){pUWGmRXmuS=aHolWAhfWTiIkl.split(QSHQrGMouv);fyUXipNh = cpmlilN[0];for(DJcKP" ascii
    $s20 = "function SKocujsTTIxqmSRFlxedNX(WitFrNr,OmxxsjMSvOw){return String.fromCharCode(WitFrNr,OmxxsjMSvOw);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}