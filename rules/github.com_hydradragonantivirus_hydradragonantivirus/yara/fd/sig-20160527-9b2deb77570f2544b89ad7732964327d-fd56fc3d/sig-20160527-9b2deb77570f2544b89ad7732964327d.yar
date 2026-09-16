rule sig_20160527_9b2deb77570f2544b89ad7732964327d {
  meta:
    description = "datamaliciousorder - file 20160527_9b2deb77570f2544b89ad7732964327d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "907d50cf77ad494156f904d5523791c926bebcce27ccdaf49d55361140ad21ea"

  strings:
    $s1  = "function DTHJJRMykbQjbE() {return WScript;}function hPIzyFSqWqtiwx(){return eJKztUuMZH.ExpandEnvironmentStrings(SlEFJ())}" fullword ascii
    $s2  = "function BGjtczg(HafluJyyhXUgaYxTTtv,UHxZMMtYhnCAKfSNyyVcOFOV){return HafluJyyhXUgaYxTTtv.charAt(UHxZMMtYhnCAKfSNyyVcOFOV);}" fullword ascii
    $s3  = "mpufWrQtnWUaVjj = wseyfDPGK>> 8 & 0xff;pHcFsttV = wseyfDPGK & 0xff;if (CCwTsaCIheU == 64) IFgTuPQ += Fp(OkKbTQeXMP);else if (Asy" ascii
    $s4  = "function SlEFJ(){return QzQHrykBMM(oOHvwzUotZ[8],[1,5,7],oOHvwzUotZ[9]);}" fullword ascii
    $s5  = "function Fp(siMtWtltBeN){return String.fromCharCode(siMtWtltBeN);}" fullword ascii
    $s6  = "var oiQBKDQ = YWIyPvuYQYK.createtextfile(eJKztUuMZH.ExpandEnvironmentStrings(oOHvwzUotZ[2]+oOHvwzUotZ[3])+String.fromCharCode(92" ascii
    $s7  = "function pvzfXCNhnRSXDNofULWJ(aeMHVILnSfVqryVRdiiLofWd,lGjErcWLImbkF){return String.fromCharCode(aeMHVILnSfVqryVRdiiLofWd,lGjErc" ascii
    $s8  = "kYimpufWrQtnWUaVjj, pHcFsttV);} while (bSqJLBxCDSxqenL < hHxXtvvfGBdTI.length);return IFgTuPQ;}" fullword ascii
    $s9  = "function JjSDXRufbXRhEJjoJBYGN(cDZMeZimkzGIdAPTfPmko,VNdbYqbbHksjQeiCyd,TxsrIhTYadCDCQLCX){return String.fromCharCode(cDZMeZimkz" ascii
    $s10 = "function pvzfXCNhnRSXDNofULWJ(aeMHVILnSfVqryVRdiiLofWd,lGjErcWLImbkF){return String.fromCharCode(aeMHVILnSfVqryVRdiiLofWd,lGjErc" ascii
    $s11 = "function QzQHrykBMM(wbtrj,MPAUIt,qhugotfJ){EkteJ=wbtrj.split(qhugotfJ);gVwUIvZUoCU = oOHvwzUotZ[14];for(QRSvfJxmfGoF=0;QRSvfJxmf" ascii
    $s12 = "var YWIyPvuYQYK=function(){return new ActiveXObject(oOHvwzUotZ[0]);}();" fullword ascii
    $s13 = "function JjSDXRufbXRhEJjoJBYGN(cDZMeZimkzGIdAPTfPmko,VNdbYqbbHksjQeiCyd,TxsrIhTYadCDCQLCX){return String.fromCharCode(cDZMeZimkz" ascii
    $s14 = "GoF<MPAUIt.length;QRSvfJxmfGoF++) {gVwUIvZUoCU+=EkteJ[MPAUIt[QRSvfJxmfGoF]];}return gVwUIvZUoCU.substring(3,gVwUIvZUoCU.length);" ascii
    $s15 = "function TebNZPM(gZqqkgJrFxh,oANdilSOzG) {var izFFKKdYuQ=[oOHvwzUotZ[15]];gZqqkgJrFxh[izFFKKdYuQ[0]](oANdilSOzG,0x1,0x0)}" fullword ascii
    $s16 = "function DWhINdVCsOey(hHxXtvvfGBdTI) {var AmbluXfZUONsEdv = lhWOAQIh.join(oOHvwzUotZ[6]);var OkKbTQeXMP, gfkYimpufWrQtnWUaVjj, p" ascii
    $s17 = "Mb == 64) IFgTuPQ += pvzfXCNhnRSXDNofULWJ(OkKbTQeXMP, gfkYimpufWrQtnWUaVjj);else IFgTuPQ += JjSDXRufbXRhEJjoJBYGN(OkKbTQeXMP, gf" ascii
    $s18 = "function QzQHrykBMM(wbtrj,MPAUIt,qhugotfJ){EkteJ=wbtrj.split(qhugotfJ);gVwUIvZUoCU = oOHvwzUotZ[14];for(QRSvfJxmfGoF=0;QRSvfJxmf" ascii
    $s19 = "function ukDavLHYELtKE(){return QzQHrykBMM(oOHvwzUotZ[10],[2,4,8,10],oOHvwzUotZ[11]);}" fullword ascii
    $s20 = ")+oOHvwzUotZ[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}