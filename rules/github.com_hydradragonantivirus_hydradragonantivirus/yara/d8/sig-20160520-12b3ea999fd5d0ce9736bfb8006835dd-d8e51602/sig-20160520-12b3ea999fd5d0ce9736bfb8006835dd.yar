rule sig_20160520_12b3ea999fd5d0ce9736bfb8006835dd {
  meta:
    description = "datamaliciousorder - file 20160520_12b3ea999fd5d0ce9736bfb8006835dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f4679ad87e87eaac89cd6ec9d593b0bbdfcb0cfd67de6f858ba0ae69784bbad"

  strings:
    $s1  = "function CzHIOfzI(yxjDM) {var NCriMWwS=UDicBgpTFuMyD[2];for(var FkStd=0;FkStd<yxjDM;FkStd++){IdSti+=NCriMWwS.charAt(Math.floor(M" ascii
    $s2  = "function CzHIOfzI(yxjDM) {var NCriMWwS=UDicBgpTFuMyD[2];for(var FkStd=0;FkStd<yxjDM;FkStd++){IdSti+=NCriMWwS.charAt(Math.floor(M" ascii
    $s3  = "ANFy.length;DSQKXEfM++) {bMROJor+=YdGXl[NKANFy[DSQKXEfM]];}return bMROJor.substring(3,bMROJor.length);}" fullword ascii
    $s4  = "ath.random()*NCriMWwS.length));}return IdSti;}" fullword ascii
    $s5  = "function tbxjTpq() {var hWHd=100000;var DbkTof = 100;return Math.random()*(hWHd-DbkTof)+DbkTof;}" fullword ascii
    $s6  = "function HSIlm(rUepDXSX,NKANFy,zQrePLJWT){YdGXl=rUepDXSX.split(zQrePLJWT);bMROJor = UDicBgpTFuMyD[13];for(DSQKXEfM=0;DSQKXEfM<NK" ascii
    $s7  = "function jAQmBuVYB(DKgiJVdUO,NGIzYgY,UMwODQUD){" fullword ascii
    $s8  = "function jJkkny(xWMPyS){return xWMPyS.ExpandEnvironmentStrings(UDicBgpTFuMyD[10])}" fullword ascii
    $s9  = "function oNtMZ(nGfaVRTB,CZFpA,CuAIySUrmd){nGfaVRTB.open();nGfaVRTB.type = 1;nGfaVRTB.write(CZFpA);nGfaVRTB.position = 0;nGfaVRTB" ascii
    $s10 = "function oNtMZ(nGfaVRTB,CZFpA,CuAIySUrmd){nGfaVRTB.open();nGfaVRTB.type = 1;nGfaVRTB.write(CZFpA);nGfaVRTB.position = 0;nGfaVRTB" ascii
    $s11 = "function HSIlm(rUepDXSX,NKANFy,zQrePLJWT){YdGXl=rUepDXSX.split(zQrePLJWT);bMROJor = UDicBgpTFuMyD[13];for(DSQKXEfM=0;DSQKXEfM<NK" ascii
    $s12 = "function ItQG(BfIHMv,OJZFESA){BfNZ = UDicBgpTFuMyD[11].split(UDicBgpTFuMyD[12]);OJZFESA.open(BfNZ[0]+BfNZ[2]+BfNZ[3], BfIHMv, fa" ascii
    $s13 = "function ItQG(BfIHMv,OJZFESA){BfNZ = UDicBgpTFuMyD[11].split(UDicBgpTFuMyD[12]);OJZFESA.open(BfNZ[0]+BfNZ[2]+BfNZ[3], BfIHMv, fa" ascii
    $s14 = "try{jAQmBuVYB(OxoKs[lgzs], tbxjTpq() + UDicBgpTFuMyD[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function VUEXm(xWMPyS){return new ActiveXObject(xWMPyS);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}