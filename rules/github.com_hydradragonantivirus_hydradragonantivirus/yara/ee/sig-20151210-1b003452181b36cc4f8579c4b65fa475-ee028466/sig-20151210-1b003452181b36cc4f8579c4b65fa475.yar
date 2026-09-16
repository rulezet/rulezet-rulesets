rule sig_20151210_1b003452181b36cc4f8579c4b65fa475 {
  meta:
    description = "datamaliciousorder - file 20151210_1b003452181b36cc4f8579c4b65fa475.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1239ec24db5a77d9c67d22ad0ef6afc2009f3c4bf6a06a42a333b6a9f7f6a25c"

  strings:
    $s1  = "function pttomSz(HhwbCXKRUDLKMDHFMkpHtgPBPrTGpduXVlrQ) {return !isNaN(parseFloat(HhwbCXKRUDLKMDHFMkpHtgPBPrTGpduXVlrQ)) && isFin" ascii
    $s2  = "function pttomSz(HhwbCXKRUDLKMDHFMkpHtgPBPrTGpduXVlrQ) {return !isNaN(parseFloat(HhwbCXKRUDLKMDHFMkpHtgPBPrTGpduXVlrQ)) && isFin" ascii
    $s3  = "}} return aLDPxnSRbWw}" fullword ascii
    $s4  = "function BXhkqaraKQYpLyVtc(zoFFI){aLDPxnSRbWw= '';for(gyhxtqTODGf=(-686+686)/451; gyhxtqTODGf < (108+110)/109; gyhxtqTODGf++) {M" ascii
    $s5  = "function BXhkqaraKQYpLyVtc(zoFFI){aLDPxnSRbWw= '';for(gyhxtqTODGf=(-686+686)/451; gyhxtqTODGf < (108+110)/109; gyhxtqTODGf++) {M" ascii
    $s6  = "CkYQkxk=(-715+715)/238;while(true){if(CkYQkxk>=(36958+802)/295){break;}rvBVcKXSDrErR[CkYQkxk]=String.fromCharCode(CkYQkxk);CkYQk" ascii
    $s7  = " gmlKv;}function OdlhrfhJooDSruT(AJbMjyCSfzgUXXikm){eval(AJbMjyCSfzgUXXikm)}" fullword ascii
    $s8  = "dcnJNCfW[gyhxtqTODGf]=(-129+129)/379; while(true) { if(MdcnJNCfW[gyhxtqTODGf] > zoFFI[gyhxtqTODGf].length-(122+705)/827) { break" ascii
    $s9  = "function ABFVXvCnrTzOXCxHGOAxqbSwcjfBSmGwuxqqVlNwcgDAJIKqXvYPps(ZIIWYSqGkcgwb,qCGRzoaASftDpL){ return rvBVcKXSDrErR[nMjQr(ZIIWYS" ascii
    $s10 = "function ABFVXvCnrTzOXCxHGOAxqbSwcjfBSmGwuxqqVlNwcgDAJIKqXvYPps(ZIIWYSqGkcgwb,qCGRzoaASftDpL){ return rvBVcKXSDrErR[nMjQr(ZIIWYS" ascii
    $s11 = "CkYQkxk=(-715+715)/238;while(true){if(CkYQkxk>=(36958+802)/295){break;}rvBVcKXSDrErR[CkYQkxk]=String.fromCharCode(CkYQkxk);CkYQk" ascii
    $s12 = "function nMjQr(ULsvSOcAbBr,cRYyxuwqCYzHH,kaNSSTAI){FWZn=parseInt(ULsvSOcAbBr,cRYyxuwqCYzHH);gmlKv=FWZn.toString(kaNSSTAI);return" ascii
    $s13 = "function HaBvbkFXNKW(vHavQcAI,pFvywY){return vHavQcAI.split(pFvywY)}" fullword ascii
    $s14 = "function nMjQr(ULsvSOcAbBr,cRYyxuwqCYzHH,kaNSSTAI){FWZn=parseInt(ULsvSOcAbBr,cRYyxuwqCYzHH);gmlKv=FWZn.toString(kaNSSTAI);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}