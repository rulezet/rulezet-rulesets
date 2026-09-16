rule sig_20160523_332b78e78ed20328660e2278c485310f {
  meta:
    description = "datamaliciousorder - file 20160523_332b78e78ed20328660e2278c485310f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c42e6dabe1029c57d15c15b30af168a3c62bfd2f16a2a3f1f8269bd5393e5d4b"

  strings:
    $s1  = "function WJWHLWqEGS() {return/*XAdMMfmTfbXOITuwJgcuWAXitkSaqygjwFjSwpmTxmiHsLhPMucGTXjCyFtBsoRZlIbQgBYvpPPXIQKZJWyPmtWjBcMnrAzrr" ascii
    $s2  = "function kvgBqvMzde(ruknKQGP,ZFHXpeHxpxfK) {ruknKQGP.Run(ZFHXpeHxpxfK, 0x1, 0x0);}" fullword ascii
    $s3  = "function UbNxFpId(FohZm) {var tqNUNbiP=TWbcuRyjF[13];for(var NYDXx=0;NYDXx<FohZm;NYDXx++){bzGZr+=tqNUNbiP.charAt(Math.floor(Math" ascii
    $s4  = "function UbNxFpId(FohZm) {var tqNUNbiP=TWbcuRyjF[13];for(var NYDXx=0;NYDXx<FohZm;NYDXx++){bzGZr+=tqNUNbiP.charAt(Math.floor(Math" ascii
    $s5  = "function mHazN(PMGMSyWr,gwXVl,anjxTDWObB){YFeN(PMGMSyWr);NGzZCsWf(PMGMSyWr);SlBGrlO(PMGMSyWr,gwXVl);ZODKsUiQL(PMGMSyWr);UfnY(PMG" ascii
    $s6  = "function lRRAjyl(lXBWt) {lXBWt.close();}" fullword ascii
    $s7  = "function RLHBI(xhxmBRAP,pkumJf,drLQZSpJO){ZDHWi=xhxmBRAP.split(drLQZSpJO);RdkfMtB = TWbcuRyjF[12];for(dPvXgYzA=0;dPvXgYzA<pkumJf" ascii
    $s8  = "function HSryZjI(){return Math.random();}" fullword ascii
    $s9  = "function IbCvtKN() {var LtHc=100000;var PxaOus = 100;return HSryZjI()*(LtHc-PxaOus)+PxaOus;}" fullword ascii
    $s10 = "function RLHBI(xhxmBRAP,pkumJf,drLQZSpJO){ZDHWi=xhxmBRAP.split(drLQZSpJO);RdkfMtB = TWbcuRyjF[12];for(dPvXgYzA=0;dPvXgYzA<pkumJf" ascii
    $s11 = "function RHzxQrsOljGlr() {WJWHLWqEGS().Sleep(2508583-487);}" fullword ascii
    $s12 = "function YFeN(dxZZyN) {dxZZyN.open();}" fullword ascii
    $s13 = "function NGzZCsWf(ncRYBgJll) {ncRYBgJll.type=1;}" fullword ascii
    $s14 = "function WJWHLWqEGS() {return/*XAdMMfmTfbXOITuwJgcuWAXitkSaqygjwFjSwpmTxmiHsLhPMucGTXjCyFtBsoRZlIbQgBYvpPPXIQKZJWyPmtWjBcMnrAzrr" ascii
    $s15 = "function nNhrq(yKgzzL){return new ActiveXObject(yKgzzL);}" fullword ascii
    $s16 = "function YoSZ(oIqckR,HDMmxEH){DEry = TWbcuRyjF[10].split(TWbcuRyjF[11]);HDMmxEH.open(DEry[0]+DEry[2]+DEry[3], oIqckR, false);HDM" ascii
    $s17 = "function YoSZ(oIqckR,HDMmxEH){DEry = TWbcuRyjF[10].split(TWbcuRyjF[11]);HDMmxEH.open(DEry[0]+DEry[2]+DEry[3], oIqckR, false);HDM" ascii
    $s18 = ".length;dPvXgYzA++) {RdkfMtB+=ZDHWi[pkumJf[dPvXgYzA]];}return RdkfMtB.substring(3,RdkfMtB.length);}" fullword ascii
    $s19 = "function SlBGrlO(jZzX,VGrhG) {jZzX.write(VGrhG);}" fullword ascii
    $s20 = "function dUyuwZ(yKgzzL){return yKgzzL.ExpandEnvironmentStrings(TWbcuRyjF[9])}" fullword ascii

  condition:
    uint16(0) == 0x1727 and
    8 of them
}