rule sig_20160524_9a449d61bb0a16bdc43e117da33e3e8f {
  meta:
    description = "datamaliciousorder - file 20160524_9a449d61bb0a16bdc43e117da33e3e8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a73cf02b67c2f8873d3a2d8f8b125f5f89594f4e2b5cde553b32f281dca98f46"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "oIgUMhRqxPNkNgaQzdjRYeszejgAiQEfbWqZdaxudcDbvyMgWnDtZVibuseOAfySjeUZMOxtciLMxKQq*/WScript;}function NEsHTyVqv(YuuLDT) {var gHlXk" ascii
    $s3  = "on xlTjixU(wYtkg) {wYtkg.close();}function fSMSpmZLMs(WpjDcLQK,nBtfeSdGxoFE) {WpjDcLQK.Run(nBtfeSdGxoFE, 0x1, 0x0);}function YkA" ascii
    $s4  = "idqzvX=VQIWe[GkcO];var oDOJJHr=YkAERjK() + FqprlHFWkpBVxUZFDUkBmzC[2];var zuMJfNpU=819-818;var LGpEeqjSu = function(){return new" ascii
    $s5  = "g.fromCharCode(92) + oDOJJHr;var AKOJZ = function(){return new ActiveXObject(GbyZi(FqprlHFWkpBVxUZFDUkBmzC[5],[0,2,4],FqprlHFWkp" ascii
    $s6  = "iU();function (tEqrunnkKGDXW) {return new ActiveXObject(tEqrunnkKGDXW);}" fullword ascii
    $s7  = "BvLSl=[];YuuLDT.position=gHlXkBvLSl.length*(9115900-736);}function eOQc(MloTqHY,bqggsJo) {MloTqHY.saveToFile(bqggsJo, 2);}functi" ascii
    $s8  = "IPgE().Sleep(5480-743);}function tJizfpX(){return Math.random();}function xcZc(vNyPSs) {vNyPSs.open();}function YbLwkezd(tQgTmEg" ascii
    $s9  = "hKr);NEsHTyVqv(ElpODgSQ);eOQc(ElpODgSQ,ytnCEpReXf);xlTjixU(ElpODgSQ);}function nXjA(VErMGY,cBLEtdd){tWeZ = FqprlHFWkpBVxUZFDUkBm" ascii
    $s10 = "3])+String.fromCharCode(92)+qUWxD;ODIlKIMrRL = JdesUXwUOGYwo.OpenTextFile(XRvdwhs,2,true);ODIlKIMrRL.Write('var FqprlHFWkpBVxUZF" ascii
    $s11 = "IWe = [FqprlHFWkpBVxUZFDUkBmzC[0], FqprlHFWkpBVxUZFDUkBmzC[1]];var GkcO=510-510;while(true) {if(GkcO>VQIWe.length) break;var ryZ" ascii
    $s12 = "UXwUOGYwo=function(){return new ActiveXObject(RUBsnoHzTnye[0]);}();var bSXAwWfcionxv=function(){return new ActiveXObject(\"WScri" ascii
    $s13 = "WY) {tQgTmEgWY.type=1;}function lvRqczK(zXqe,kmsfJ) {zXqe.write(kmsfJ);}function SUmTnpIPgE() {return/*elwsnyHJtuLiishVRiTAgjucm" ascii
    $s14 = "ERjK() {var afWZ=100000;var wapqxo = 100;return tJizfpX()*(afWZ-wapqxo)+wapqxo;}function GkigMDhn(aVBVo) {var jUPTSqhH=FqprlHFWk" ascii
    $s15 = "ngs(FqprlHFWkpBVxUZFDUkBmzC[9])}function qcjMl(ElpODgSQ,aAhKr,ytnCEpReXf){ElpODgSQ.open();YbLwkezd(ElpODgSQ);lvRqczK(ElpODgSQ,aA" ascii
    $s16 = "ngth;tBuQGLlZ++) {JuFqGjM+=gILUG[PeYAxS[tBuQGLlZ]];}return JuFqGjM.substring(3,JuFqGjM.length);}function OsqPsFrwdvxVm() {SUmTnp" ascii
    $s17 = "zC[10].split(FqprlHFWkpBVxUZFDUkBmzC[11]);cBLEtdd.open(tWeZ[0]+tWeZ[2]+tWeZ[3], VErMGY, false);cBLEtdd.send();}function GbyZi(IF" ascii
    $s18 = "a\\x6d\\x50\\x64\\x76\\x69\\x57\\x6d\\x44\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function tgOQQoAOPyCFiU() {v" ascii
    $s19 = "n mCEAw;}function HyyuijOWgexhmA(YgNppwuOUjsRNZ) {return new ActiveXObject(YgNppwuOUjsRNZ);}');var hdJVTsynBituiOhU=[\"\\x77\\x7" ascii
    $s20 = "BVxUZFDUkBmzC[6]));}();nXjA(ryZidqzvX,AKOJZ);if (AKOJZ.status == 100+100) {var ZpHZRkP = function() {return new ActiveXObject(Gb" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}