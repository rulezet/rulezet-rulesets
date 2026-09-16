rule sig_20151215_2f2e23e9b53ee2aabe134b4b3129258a {
  meta:
    description = "datamaliciousorder - file 20151215_2f2e23e9b53ee2aabe134b4b3129258a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49d09158ae2fb259a20037bc8aa6ada4dbafa7a81eb60edc4267b4d6e96d565f"

  strings:
    $s1  = "th.pow(Math.cos(58), 2) - 1)); while(true) { if(FpyOhwrDI[ODkZfjLxKxU] > eOixl[ODkZfjLxKxU].length-(661+293)/954) { break; } if " ascii
    $s2  = "(Math.cos(253), 2) - 1)));} FpyOhwrDI[ODkZfjLxKxU]++;}} return AqwhGJcafEb}" fullword ascii
    $s3  = "function vgEzugpsJlOxLiHne(eOixl){AqwhGJcafEb= r[1787];for(ODkZfjLxKxU=Math.round((Math.pow(Math.sin(958), 2) + Math.pow(Math.co" ascii
    $s4  = "tuWl)) {return (String.fromCharCode(zvxYKyYdJYmQtuWl) + String.fromCharCode((31707+741)/676));}}" fullword ascii
    $s5  = "function H(IADtYTwuhVND,KvvElnDwLvyfjh){IADtYTwuhVND.push(KvvElnDwLvyfjh);}function W8(zvxYKyYdJYmQtuWl){if(YrVryhb(zvxYKyYdJYmQ" ascii
    $s6  = "function vgEzugpsJlOxLiHne(eOixl){AqwhGJcafEb= r[1787];for(ODkZfjLxKxU=Math.round((Math.pow(Math.sin(958), 2) + Math.pow(Math.co" ascii
    $s7  = "function YrVryhb(DhqCmUfheubTOPIfSTlOLVOcqRqAblfNiyHs) {return !isNaN(parseFloat(DhqCmUfheubTOPIfSTlOLVOcqRqAblfNiyHs)) && isFin" ascii
    $s8  = "function YrVryhb(DhqCmUfheubTOPIfSTlOLVOcqRqAblfNiyHs) {return !isNaN(parseFloat(DhqCmUfheubTOPIfSTlOLVOcqRqAblfNiyHs)) && isFin" ascii
    $s9  = "var r=new Array();" fullword ascii
    $s10 = "function huyzD(aGZTLnxmYkJ,ESnqawNPBSbrl,mnSEXTCR){kWPu=parseInt(aGZTLnxmYkJ,ESnqawNPBSbrl);bpjPP=kWPu.toString(mnSEXTCR);return" ascii
    $s11 = "function NVwhktKeLWrICLRNQuNaMkimkSOYONfvCcfZbfLHKHQKdOtSdyDPVo(oSFABjrOYLBJV,hCsxnClkmoOxrC){ return CEvHGjZ[LQcTQXVf[huyzD(oSF" ascii
    $s12 = "function VxpzFKDqdYr(LHzpgwrK,johmLC){return LHzpgwrK.split(johmLC)}" fullword ascii
    $s13 = "function huyzD(aGZTLnxmYkJ,ESnqawNPBSbrl,mnSEXTCR){kWPu=parseInt(aGZTLnxmYkJ,ESnqawNPBSbrl);bpjPP=kWPu.toString(mnSEXTCR);return" ascii
    $s14 = "function H(IADtYTwuhVND,KvvElnDwLvyfjh){IADtYTwuhVND.push(KvvElnDwLvyfjh);}function W8(zvxYKyYdJYmQtuWl){if(YrVryhb(zvxYKyYdJYmQ" ascii
    $s15 = "function NVwhktKeLWrICLRNQuNaMkimkSOYONfvCcfZbfLHKHQKdOtSdyDPVo(oSFABjrOYLBJV,hCsxnClkmoOxrC){ return CEvHGjZ[LQcTQXVf[huyzD(oSF" ascii
    $s16 = " bpjPP;}function DvSGqPeHELOoVry(UCOrYOfiiZoHyQtuO,SiOrOkyVUqfkFxYFFTBBVAWRkldWyNCYUv,BhvDirKNdRnwRuvhlVOuvWqsuSphEXuoGte){eval(" ascii
    $s17 = "function DvSGqPeHELOoVry(UCOrYOfiiZoHyQtuO){eval(UCOrYOfiiZoHyQtuO)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}