rule sig_20160531_327baf6e4842335a81ee3683a1051b8f {
  meta:
    description = "datamaliciousorder - file 20160531_327baf6e4842335a81ee3683a1051b8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2640c28f3f848636f7d9e248d1d112c27b2ffa8cabbbf5cab2d6d95802aa6fc"

  strings:
    $s1  = "var CDDWz=function(){return WScript.CreateObject(dpQDTOcZjDs[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ooXyWnoZiwbYGo(ElFFAOcMGNqQzG,myyfqSHZkoUeILtEnAJfU){return ElFFAOcMGNqQzG.charAt(myyfqSHZkoUeILtEnAJfU);}" fullword ascii
    $s3  = "eVIlAozTKMU += gRc(FUjjBbkTcMnednGw);else if (ECFhqncobFxDZvSprqeYjA == 64) tZweVIlAozTKMU += jJwBwtmfWPteprviDXnv(FUjjBbkTcMned" ascii
    $s4  = "xcpW < tzTHrVKBATFUN.length);return tZweVIlAozTKMU;}" fullword ascii
    $s5  = "function MMmeQEVR(tzTHrVKBATFUN) {var JxFhMmaCxooVharpcQVChMw = XiVvxeAOHcyORYxZCEhR.join(dpQDTOcZjDs[7]);var FUjjBbkTcMnednGw, " ascii
    $s6  = "nGw, LdSSadRgKfuYZkysqgJ);else tZweVIlAozTKMU += dLPnxi(FUjjBbkTcMnednGw, LdSSadRgKfuYZkysqgJ, DcargnDqyVUd);} while (rWJFiZFovt" ascii
    $s7  = "function dLPnxi(bJjKFTSLqMHBP,QpNvaqNGBIsdmAmlMVLwe,eUdhHMXFSoaGCTwaZF){return String.fromCharCode(bJjKFTSLqMHBP,QpNvaqNGBIsdmAm" ascii
    $s8  = "function LvlXy(tXRDhZyXkBFY,BnJamhoA,IglFYd){qrJpoNwEmAxKqr=tXRDhZyXkBFY.split(IglFYd);tDwrMIs = dpQDTOcZjDs[0];for(zPddjYJILKbz" ascii
    $s9  = "function gRc(dhAdrvvcNmt){return String.fromCharCode(dhAdrvvcNmt);}" fullword ascii
    $s10 = "(NjhCruaM,0x1,0x0)}function eMRCyDV(VrzdxXJamTj,sMTax,cIUiUeD){var xOMUGolRQppHUx=VrzdxXJamTj.createtextfile(sMTax,true);xOMUGol" ascii
    $s11 = "function JxWAsPbhAOLfDSAYjSpBrTd(ELtnsJ,MMfvRapHf){return ELtnsJ.indexOf(MMfvRapHf);}" fullword ascii
    $s12 = "function MMmeQEVR(tzTHrVKBATFUN) {var JxFhMmaCxooVharpcQVChMw = XiVvxeAOHcyORYxZCEhR.join(dpQDTOcZjDs[7]);var FUjjBbkTcMnednGw, " ascii
    $s13 = "function DgNmmleZuUgA(){return LvlXy(dpQDTOcZjDs[9],[1,5,7],dpQDTOcZjDs[10]);}" fullword ascii
    $s14 = "s=0;zPddjYJILKbzs<BnJamhoA.length;zPddjYJILKbzs++) {tDwrMIs+=qrJpoNwEmAxKqr[BnJamhoA[zPddjYJILKbzs]];}return tDwrMIs.substring(3" ascii
    $s15 = "function LvlXy(tXRDhZyXkBFY,BnJamhoA,IglFYd){qrJpoNwEmAxKqr=tXRDhZyXkBFY.split(IglFYd);tDwrMIs = dpQDTOcZjDs[0];for(zPddjYJILKbz" ascii
    $s16 = "var ldNlXEy=function(){return new ActiveXObject(dpQDTOcZjDs[1]);}();" fullword ascii
    $s17 = "function jJwBwtmfWPteprviDXnv(KfsVEVbXfFkPjp,yharCp){return String.fromCharCode(KfsVEVbXfFkPjp,yharCp);}" fullword ascii
    $s18 = "function zywQDleGwgmi(){return LvlXy(dpQDTOcZjDs[13],[0,3,6],dpQDTOcZjDs[14]);}" fullword ascii
    $s19 = "function dLPnxi(bJjKFTSLqMHBP,QpNvaqNGBIsdmAmlMVLwe,eUdhHMXFSoaGCTwaZF){return String.fromCharCode(bJjKFTSLqMHBP,QpNvaqNGBIsdmAm" ascii
    $s20 = "(NjhCruaM,0x1,0x0)}function eMRCyDV(VrzdxXJamTj,sMTax,cIUiUeD){var xOMUGolRQppHUx=VrzdxXJamTj.createtextfile(sMTax,true);xOMUGol" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}