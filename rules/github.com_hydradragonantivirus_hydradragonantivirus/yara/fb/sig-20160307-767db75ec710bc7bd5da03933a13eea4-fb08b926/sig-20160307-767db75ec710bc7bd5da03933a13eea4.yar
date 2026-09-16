rule sig_20160307_767db75ec710bc7bd5da03933a13eea4 {
  meta:
    description = "datamaliciousorder - file 20160307_767db75ec710bc7bd5da03933a13eea4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75b911e9aa391ef8cb8a1296d00b46db8e30db06eb4454a0643326c54d411ad1"

  strings:
    $s1  = "return gB.ExpandEnvironmentStrings(HuRAT[6]+HuRAT[7]+HuRAT[8]);" fullword ascii
    $s2  = "var Kv = true  , nbwG = zBz[7] + zBz[9] + zBz[11];" fullword ascii
    $s3  = "return RXBzrya[0] + RXBzrya[2] + RXBzrya[4] + \".F\" + RXBzrya[7] + RXBzrya[9] + RXBzrya[12] + RXBzrya[14];" fullword ascii
    $s4  = "var RXBzrya = \"Sc xfWGdGi r cePcJCJGG ipting XYuPMwy jDz ile WlDjPFLHdWvZXl System DE nUnaH Obj nctMVm ect umjlQrj\".split(\" " ascii
    $s5  = "pwbYq.open(dVzrM,vneHM,false);" fullword ascii
    $s6  = "var zBz = (\"2.XMLHTTP vtJOEac ENwOk XML ream St keadrYRl AD OOYQCed O NOQU D\").split(\" \");" fullword ascii
    $s7  = "function vDDv(exCUc) {" fullword ascii
    $s8  = "mDU = p; break; " fullword ascii
    $s9  = "if (J >= exCUc.length) {break;}" fullword ascii
    $s10 = "function hQUtseDr() {" fullword ascii
    $s11 = "if (((new Date())>0,7413010888)) {" fullword ascii
    $s12 = "return EPTjdvP" fullword ascii
    $s13 = "function ranB(RCmUs) {" fullword ascii
    $s14 = "if (rvlZP > 165233-832){return true;} else {return false;}" fullword ascii
    $s15 = "function JYDNM(TsxqLI) {" fullword ascii
    $s16 = "function KhzmUsNhG(FgLVq,lOODV,NcPXe,hwtV) {" fullword ascii
    $s17 = "function uilH(WSYuH,qPgyO) {" fullword ascii
    $s18 = "function vJwd(pwbYq,vneHM,dVzrM) {" fullword ascii
    $s19 = "function jbbjwLF(AhHh) {" fullword ascii
    $s20 = "if(p>=V.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}