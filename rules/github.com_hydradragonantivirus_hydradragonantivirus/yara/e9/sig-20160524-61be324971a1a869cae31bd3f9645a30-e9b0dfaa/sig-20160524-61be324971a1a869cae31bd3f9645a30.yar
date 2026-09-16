rule sig_20160524_61be324971a1a869cae31bd3f9645a30 {
  meta:
    description = "datamaliciousorder - file 20160524_61be324971a1a869cae31bd3f9645a30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b816fdfe42aeece16e5c24989bba132cd1bae75536538290ebc4938fa1b312"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "turn new ActiveXObject(BXHkEtWRt[0]);}();var LeGJUyYAIm=function(){return new ActiveXObject(\"WScript.Shell\");}();var DZxgImkch" ascii
    $s3  = "\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];LyMfbyd.Close();LeGJUyYAIm.Run(ljpmLn[0]+QgHtFQvys,0x1,0x0);}yKOWLGtN();function (SGhkItY" ascii
    $s4  = "VtRwQzXlLuTHfjQDUxyqFoeMkntkgADAsFrbsHXFglfEfwbPnSwFeFBQBocQdWlwIkMaOiRtuvlUZcgvAHnnwqRo*/WScript;}function jBvWxIfiF(YxweBJ) {v" ascii
    $s5  = ";}function DBxRZJc(wttqE) {wttqE.close();}function DDTbUKQalP(MkToLSKh,tIdSNTOtBjli) {MkToLSKh.Run(tIdSNTOtBjli, 0x1, 0x0);}func" ascii
    $s6  = "aSfxRe() + kQzTSQVNkLSsbPR[2];var ljQyCGgF=242-241;var FNhLMcZcQ = function(){return new ActiveXObject(DCYOu(kQzTSQVNkLSsbPR[3]," ascii
    $s7  = "[0,2,4],kQzTSQVNkLSsbPR[4]));}();var YANPxHE = SDYOPC(FNhLMcZcQ) + String.fromCharCode(92) + YANPxHE;var UBGWl = function(){retu" ascii
    $s8  = "JjpaY.length;MLrSTwET++) {gfSgDdM+=aeQhz[sJjpaY[MLrSTwET]];}return gfSgDdM.substring(3,gfSgDdM.length);}function MIFQTMMMRjZsd()" ascii
    $s9  = "LSsbPR[0], kQzTSQVNkLSsbPR[1]];var VTPI=973-973;while(true) {if(VTPI>qNcOm.length) break;var ZtzTOORnW=qNcOm[VTPI];var YANPxHE=N" ascii
    $s10 = "fYA){return sUefYA.ExpandEnvironmentStrings(kQzTSQVNkLSsbPR[9])}function sarCB(ShdvSlpZ,DoGKf,CUCcLvZzbd){ShdvSlpZ.open();akZRBs" ascii
    $s11 = "n MHPBz;}function kKKCtuQBYKSVsg(UXrECsoETqbeAE) {return new ActiveXObject(UXrECsoETqbeAE);}');var ljpmLn=[\"\\x77\\x73\\x63\\x7" ascii
    $s12 = "iy){FsCp = kQzTSQVNkLSsbPR[10].split(kQzTSQVNkLSsbPR[11]);AGCLDiy.open(FsCp[0]+FsCp[2]+FsCp[3], bOyDcq, false);AGCLDiy.send();}f" ascii
    $s13 = "kb(ShdvSlpZ);XkBPwHK(ShdvSlpZ,DoGKf);jBvWxIfiF(ShdvSlpZ);jwdr(ShdvSlpZ,CUCcLvZzbd);DBxRZJc(ShdvSlpZ);}function Zcli(bOyDcq,AGCLD" ascii
    $s14 = "56\\x58\\x61\\x6f\\x54\\x4c\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function yKOWLGtN() {var LyMfbyd;var rukod" ascii
    $s15 = "(YHRiJBYvA) {YHRiJBYvA.type=1;}function XkBPwHK(uUSK,HQXJs) {uUSK.write(HQXJs);}function LRkkXAeYqy() {return/*KvuuvaqBcMGEXcxOX" ascii
    $s16 = "ar DUWBUypkpO=[];YxweBJ.position=DUWBUypkpO.length*(3005364-878);}function jwdr(KvfcxTL,wAbNwyG) {KvfcxTL.saveToFile(wAbNwyG, 2)" ascii
    $s17 = "xgImkchttCPM;LyMfbyd = rukodFKTgM.OpenTextFile(QgHtFQvys,2,true);LyMfbyd.Write('var kQzTSQVNkLSsbPR=[\"\\x68\\x74\\x74\\x70\\x3a" ascii
    $s18 = " {LRkkXAeYqy().Sleep(4505-994);}function aRUSten(){return Math.random();}function seTT(VRDjES) {VRDjES.open();}function akZRBskb" ascii
    $s19 = "unction DCYOu(RbqQOuCJ,sJjpaY,yBLTgMYxr){aeQhz=RbqQOuCJ.split(yBLTgMYxr);gfSgDdM = kQzTSQVNkLSsbPR[12];for(MLrSTwET=0;MLrSTwET<s" ascii
    $s20 = ") {var MkNqFnz = function() {return new ActiveXObject(DCYOu(kQzTSQVNkLSsbPR[7],[0,2,4],kQzTSQVNkLSsbPR[8]));}();sarCB(MkNqFnz,UB" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}