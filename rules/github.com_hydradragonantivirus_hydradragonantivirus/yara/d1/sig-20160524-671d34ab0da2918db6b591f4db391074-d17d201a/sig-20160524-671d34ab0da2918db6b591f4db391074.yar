rule sig_20160524_671d34ab0da2918db6b591f4db391074 {
  meta:
    description = "datamaliciousorder - file 20160524_671d34ab0da2918db6b591f4db391074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f6831cab39fffea759a672c6696a06e9411aa8d323983b5b9df99c54520c0c8"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "pHVe.close();}function KJwgMiSkpf(MZIWjLLH,PhPJIxMcusUj) {MZIWjLLH.Run(PhPJIxMcusUj, 0x1, 0x0);}function dhQzYQb() {var GtrZ=100" ascii
    $s3  = "=function(){return new ActiveXObject(xPAveeYLHd[0]);}();var rgvvBPkdcnpHF=function(){return new ActiveXObject(\"WScript.Shell\")" ascii
    $s4  = "xVGYBYakUzKazbxKQKygQfyHZrIenXOPhebHErhWcNrBAYqNxeqzQHccePLp*/WScript;}function ZbKlFGyJE(VwIwWN) {var adqkdZgYJh=[];VwIwWN.posi" ascii
    $s5  = "e\\x65\\x78\\x65\\x20\"];NVYVmlvbR.Close();rgvvBPkdcnpHF.Run(tLclGkftTWULTPRPqdpL[0]+bQFKFDH,0x1,0x0);}EIDFSWnyR();function (CWk" ascii
    $s6  = "if(cZsN>brRoB.length) break;var ZTVrAFMRU=brRoB[cZsN];var HuWyyZS=dhQzYQb() + QBJNZYKwMjWzHKxfZG[2];var gcgqiRUC=763-762;var wQU" ascii
    $s7  = "o(wQUnpxkJE) + String.fromCharCode(92) + HuWyyZS;var QXual = function(){return new ActiveXObject(InmlL(QBJNZYKwMjWzHKxfZG[5],[0," ascii
    $s8  = "ZbKlFGyJE(jaIGGigb);ZOjb(jaIGGigb,iIPlXUDhsN);CGFIjGi(jaIGGigb);}function vIgE(PTykIt,fZAnnMo){fHRx = QBJNZYKwMjWzHKxfZG[10].spl" ascii
    $s9  = "r OcNbj=0;OcNbj<KOZrY;OcNbj++){CRLIV+=wmftVJPV.charAt(Math.floor(Math.random()*wmftVJPV.length));}return CRLIV;}function BnXEvoB" ascii
    $s10 = "omCharCode(92)+mvpMcelrP;NVYVmlvbR = tpSecL.OpenTextFile(bQFKFDH,2,true);NVYVmlvbR.Write('var QBJNZYKwMjWzHKxfZG=[\"\\x68\\x74" ascii
    $s11 = "2,4],QBJNZYKwMjWzHKxfZG[6]));}();vIgE(ZTVrAFMRU,QXual);if (QXual.status == 100+100) {var uQRWYlb = function() {return new Active" ascii
    $s12 = "npxkJE = function(){return new ActiveXObject(InmlL(QBJNZYKwMjWzHKxfZG[3],[0,2,4],QBJNZYKwMjWzHKxfZG[4]));}();var HuWyyZS = MDxlo" ascii
    $s13 = "1;}function uRwlkLL(bAVp,ZOztW) {bAVp.write(ZOztW);}function deedntJjev() {return/*ByhWXvBiPYQQwGffIsZMSFEXSrxyacLAhKWNFNmynjksw" ascii
    $s14 = "7\\x57\\x44\\x57\\x4c\\x65\\x72\\x6d\\x5a\\x57\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function EIDFSWnyR() {v" ascii
    $s15 = "NgoGA) {return new ActiveXObject(CWkmwcdVNgoGA);}" fullword ascii
    $s16 = "4);}function DPELCNo(){return Math.random();}function KrNM(lJjusP) {lJjusP.open();}function RmMtdNvI(LTatifGLl) {LTatifGLl.type=" ascii
    $s17 = "ngs(QBJNZYKwMjWzHKxfZG[9])}function tsEwu(jaIGGigb,qQjfq,iIPlXUDhsN){jaIGGigb.open();RmMtdNvI(jaIGGigb);uRwlkLL(jaIGGigb,qQjfq);" ascii
    $s18 = "ImxCHrk(cOBAINkSyQikdJ) {return new ActiveXObject(cOBAINkSyQikdJ);}');var tLclGkftTWULTPRPqdpL=[\"\\x77\\x73\\x63\\x72\\x69\\x70" ascii
    $s19 = "lXATtSxqGyJkkHigQLtiL*/ledDLHqJAdibe();var brRoB = [QBJNZYKwMjWzHKxfZG[0], QBJNZYKwMjWzHKxfZG[1]];var cZsN=265-265;while(true) {" ascii
    $s20 = "it(QBJNZYKwMjWzHKxfZG[11]);fZAnnMo.open(fHRx[0]+fHRx[2]+fHRx[3], PTykIt, false);fZAnnMo.send();}function InmlL(uosTJgIW,etVoeh,p" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}