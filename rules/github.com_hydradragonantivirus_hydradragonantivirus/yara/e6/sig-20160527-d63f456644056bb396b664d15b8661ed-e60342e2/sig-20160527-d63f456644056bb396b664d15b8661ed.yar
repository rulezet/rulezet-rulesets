rule sig_20160527_d63f456644056bb396b664d15b8661ed {
  meta:
    description = "datamaliciousorder - file 20160527_d63f456644056bb396b664d15b8661ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8606441e135a4d035fce03bb33507c31356e051e3e52b61cfa5688333039c390"

  strings:
    $s1  = "function nAORaLB() {return WScript;}function dBZYzJ(){return JPTAYg.ExpandEnvironmentStrings(hzwsYoZkwG())}" fullword ascii
    $s2  = "function sBUGWIoiEWjXE(aXrCqyh,iWiRqdTzDkDxdcFLLjApcJ){return aXrCqyh.charAt(iWiRqdTzDkDxdcFLLjApcJ);}" fullword ascii
    $s3  = "function mJxmIZhJsDVSj(yndFeIIytoANeiep,HgONZCMdDUtZ){return String.fromCharCode(yndFeIIytoANeiep,HgONZCMdDUtZ);}" fullword ascii
    $s4  = "function DAscxgPlYtMTRBNQrRaib(TfhvYBDxDwlLOcOpStalfIBc,rTHOSFh,qprRxU){return String.fromCharCode(TfhvYBDxDwlLOcOpStalfIBc,rTHO" ascii
    $s5  = "xVQz == 64) uhXopPOlnApe += mJxmIZhJsDVSj(PHmFzJxYyL, jmGcWNrTgCtluQlYCC);else uhXopPOlnApe += DAscxgPlYtMTRBNQrRaib(PHmFzJxYyL," ascii
    $s6  = "function wkOVDkjMjaTcJokPOSEwIQaO(hVWjrppVXGMUETDgcoZiZq,BiZWpXSgDHRZIIVu){return hVWjrppVXGMUETDgcoZiZq.indexOf(BiZWpXSgDHRZIIV" ascii
    $s7  = "function wkOVDkjMjaTcJokPOSEwIQaO(hVWjrppVXGMUETDgcoZiZq,BiZWpXSgDHRZIIVu){return hVWjrppVXGMUETDgcoZiZq.indexOf(BiZWpXSgDHRZIIV" ascii
    $s8  = "=0;KqagMO<DveDELpSiAGn.length;KqagMO++) {HLrrrkxb+=vdlZB[DveDELpSiAGn[KqagMO]];}return HLrrrkxb.substring(3,HLrrrkxb.length);}" fullword ascii
    $s9  = "function C(uVipPejGUwb){return String.fromCharCode(uVipPejGUwb);}" fullword ascii
    $s10 = "function fhpioXFQ(UjSEWzmiFo,DveDELpSiAGn,gbOUjKPUKUwya){vdlZB=UjSEWzmiFo.split(gbOUjKPUKUwya);HLrrrkxb = KTUzdBz[14];for(KqagMO" ascii
    $s11 = "function aiFxBJv(mmYnvlKjgdh,krAXZdIwnLXSt) {var qjDMuFZAHIp=[KTUzdBz[15]];mmYnvlKjgdh[qjDMuFZAHIp[0]](krAXZdIwnLXSt,0x1,0x0)}" fullword ascii
    $s12 = "function DAscxgPlYtMTRBNQrRaib(TfhvYBDxDwlLOcOpStalfIBc,rTHOSFh,qprRxU){return String.fromCharCode(TfhvYBDxDwlLOcOpStalfIBc,rTHO" ascii
    $s13 = "function COEmg(){return fhpioXFQ(KTUzdBz[12],[0,3,6],KTUzdBz[13]);}" fullword ascii
    $s14 = "var CTGijC=function(){return new ActiveXObject(KTUzdBz[0]);}();" fullword ascii
    $s15 = "push(\"v\");oCjznNTzqUuLdVPBEaAZWcZQ.push(\"w\");oCjznNTzqUuLdVPBEaAZWcZQ.push(\"x\");oCjznNTzqUuLdVPBEaAZWcZQ.push(\"y\");oCjzn" ascii
    $s16 = "var JPTAYg=function(){return nAORaLB().CreateObject(KTUzdBz[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "function SPvtIDesKElosd(wjurCOwQeqjxk) {var IJPVwAzgfeXjxKaoTBTdX = oCjznNTzqUuLdVPBEaAZWcZQ.join(KTUzdBz[6]);var PHmFzJxYyL, jm" ascii
    $s18 = "function SPvtIDesKElosd(wjurCOwQeqjxk) {var IJPVwAzgfeXjxKaoTBTdX = oCjznNTzqUuLdVPBEaAZWcZQ.join(KTUzdBz[6]);var PHmFzJxYyL, jm" ascii
    $s19 = " jmGcWNrTgCtluQlYCC, FocEldifhTEbDHplSh);} while (ZUSgkPsYVODyOFi < wjurCOwQeqjxk.length);return uhXopPOlnApe;}" fullword ascii
    $s20 = "TEbDHplSh = mBPyAkXqXHTKmgpJaqDGteT & 0xff;if (AcvvaKxQZVTGRGbOdFH == 64) uhXopPOlnApe += C(PHmFzJxYyL);else if (MWZjuelZaDHRQzk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}