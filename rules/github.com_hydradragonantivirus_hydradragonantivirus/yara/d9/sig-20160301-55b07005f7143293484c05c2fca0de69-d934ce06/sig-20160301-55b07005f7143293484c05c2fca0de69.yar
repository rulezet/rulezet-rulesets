rule sig_20160301_55b07005f7143293484c05c2fca0de69 {
  meta:
    description = "datamaliciousorder - file 20160301_55b07005f7143293484c05c2fca0de69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af06254321ddd0e194564735b8cbaf0060e35c2d3a974a72bc5eaf751b1877ef"

  strings:
    $s1  = "var Bd = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(fgNsV);" fullword ascii
    $s3  = "var NgJ = (fnz + \"TTP\" + \" sqUUPmk RMMPu XML ream St YUIJkCxq AD BqBlzgJ OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + xglnAnv + \".F\" + qfivrnidjV + lbeWz + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var gl = true  , bLIs = NgJ[7] + \"\" + NgJ[9];" fullword ascii
    $s6  = "function BxuPBkfye(LRlcL,OwngG,DICoM) {" fullword ascii
    $s7  = "ZImWk.open(wgWyo,UwmrP,false);" fullword ascii
    $s8  = "function cFKv(SOKWl) {" fullword ascii
    $s9  = "function nodN(EUznz,WgFRe) {" fullword ascii
    $s10 = "if (((new Date())>0,7495162888)) {" fullword ascii
    $s11 = "function bvJz(meNoq) {" fullword ascii
    $s12 = "return BtfbH.status;" fullword ascii
    $s13 = "function kwPR(OetpE) {" fullword ascii
    $s14 = "if(P>=v.length) {break;}" fullword ascii
    $s15 = "function PpnVSoVy() {" fullword ascii
    $s16 = "if (meNoq > 171532-543){return true;} else {return false;}" fullword ascii
    $s17 = "if (SOKWl == 704-504){return true;} else {return false;}" fullword ascii
    $s18 = "function cSmL(TEdKv) {" fullword ascii
    $s19 = "return cPwzY;" fullword ascii
    $s20 = "function IlTpo(HQRRhn) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}