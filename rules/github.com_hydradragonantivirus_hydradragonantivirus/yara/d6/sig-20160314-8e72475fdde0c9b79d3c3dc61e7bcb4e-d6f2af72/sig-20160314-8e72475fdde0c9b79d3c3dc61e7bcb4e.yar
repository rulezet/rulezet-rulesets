rule sig_20160314_8e72475fdde0c9b79d3c3dc61e7bcb4e {
  meta:
    description = "datamaliciousorder - file 20160314_8e72475fdde0c9b79d3c3dc61e7bcb4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa52d1f5cb11c3c0c22f9b796fdbbf4cf86bc2675cd38425d29913bc0bd76b14"

  strings:
    $s1  = "var bF = true  , agup = lRt[7] + lRt[9] + lRt[11];" fullword ascii
    $s2  = "return MhPrMzt[0] + MhPrMzt[2] + MhPrMzt[4] + \".F\" + MhPrMzt[7] + MhPrMzt[9] + MhPrMzt[12] + MhPrMzt[14];" fullword ascii
    $s3  = "var MhPrMzt = \"Sc HWUZcKY r OjHoRbGyY ipting ULJvhqO Hgs ile vUxLBogUJtwqXp System uq FYERF Obj LRmMZb ect iOXsLrn omFDo\".spli" ascii
    $s4  = "RTsde.open(WtNfm,fIdDB,false);" fullword ascii
    $s5  = "var lRt = (\"2.XMLHTTP znLttur ipyuv XML ream St YYjWQDcR AD crCLbqt O CbLn D\").split(\" \");" fullword ascii
    $s6  = "var MhPrMzt = \"Sc HWUZcKY r OjHoRbGyY ipting ULJvhqO Hgs ile vUxLBogUJtwqXp System uq FYERF Obj LRmMZb ect iOXsLrn omFDo\".spli" ascii
    $s7  = "if (BiQMU > 183752-646){return true;} else {return false;}" fullword ascii
    $s8  = "function QePTfoe(GHEM,PcWtm) {" fullword ascii
    $s9  = "function XnGb(BiQMU) {" fullword ascii
    $s10 = "function dzzo(FLUYi,gJNFB) {" fullword ascii
    $s11 = "if (n >= QszQx.length) {break;}" fullword ascii
    $s12 = "return hLR.size;" fullword ascii
    $s13 = "oph = W; break; " fullword ascii
    $s14 = "function enRI(RfhsE) {" fullword ascii
    $s15 = "function ZHZax(mZkqVs) {" fullword ascii
    $s16 = "function fToGhIBDm(fGjjvNVhcnE) {" fullword ascii
    $s17 = "function wCuP(CmJFY) {" fullword ascii
    $s18 = "function eBjIliYI() {" fullword ascii
    $s19 = "function ADCe(RTsde,fIdDB,WtNfm) {" fullword ascii
    $s20 = "function LJwiZoczp() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}