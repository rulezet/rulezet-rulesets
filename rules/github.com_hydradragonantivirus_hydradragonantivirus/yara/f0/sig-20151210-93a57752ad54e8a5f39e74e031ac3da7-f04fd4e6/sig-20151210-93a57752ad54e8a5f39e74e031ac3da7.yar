rule sig_20151210_93a57752ad54e8a5f39e74e031ac3da7 {
  meta:
    description = "datamaliciousorder - file 20151210_93a57752ad54e8a5f39e74e031ac3da7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf42ea08dad0c1b3c5facdad28c939cdea276c7c32640be1fccd51db69b453ca"

  strings:
    $s1  = "function eVDCFQc(jKXYRDrHGEizVlhVlSxhOKkTQgwzJwGVGwxP) {return !isNaN(parseFloat(jKXYRDrHGEizVlhVlSxhOKkTQgwzJwGVGwxP)) && isFin" ascii
    $s2  = "function eVDCFQc(jKXYRDrHGEizVlhVlSxhOKkTQgwzJwGVGwxP) {return !isNaN(parseFloat(jKXYRDrHGEizVlhVlSxhOKkTQgwzJwGVGwxP)) && isFin" ascii
    $s3  = "++;}} return rahlLsjVdVU}" fullword ascii
    $s4  = "function YwegVozoUvZ(YkmghOzb,qVmPHo){return YkmghOzb.split(qVmPHo)}" fullword ascii
    $s5  = "function dBICe(QBDezuxvFcO,LuBobVwhoInCy,bmtdZaIr){NWER=parseInt(QBDezuxvFcO,LuBobVwhoInCy);kPYiy=NWER.toString(bmtdZaIr);return" ascii
    $s6  = "UylbomE=(-360+360)/787;while(true){if(UylbomE>=(54292+876)/431){break;}NUHwTqvtjUntc[UylbomE]=String.fromCharCode(UylbomE);Uylbo" ascii
    $s7  = "function CYGWilnFeqtsAJYaN(PYguy){rahlLsjVdVU= '';for(pArieNZxIIb=(-673+673)/434; pArieNZxIIb < (1222+566)/894; pArieNZxIIb++) {" ascii
    $s8  = " kPYiy;}function spcglrdrMoFhyJp(ygMtSvSrSwdlExkos){eval(ygMtSvSrSwdlExkos)}" fullword ascii
    $s9  = "function dBICe(QBDezuxvFcO,LuBobVwhoInCy,bmtdZaIr){NWER=parseInt(QBDezuxvFcO,LuBobVwhoInCy);kPYiy=NWER.toString(bmtdZaIr);return" ascii
    $s10 = "MRGTgQqdv[pArieNZxIIb]=(-614+614)/809; while(true) { if(MRGTgQqdv[pArieNZxIIb] > PYguy[pArieNZxIIb].length-(-190+796)/606) { bre" ascii
    $s11 = "UylbomE=(-360+360)/787;while(true){if(UylbomE>=(54292+876)/431){break;}NUHwTqvtjUntc[UylbomE]=String.fromCharCode(UylbomE);Uylbo" ascii
    $s12 = "function dKLcAEeTYietGykescvRVAZTGFXwEkMSaBSVAIWqTirgszxuEfJAHe(TfyUZHeipaxIR,rOouhdquKJEkSg){ return NUHwTqvtjUntc[dBICe(TfyUZH" ascii
    $s13 = "function CYGWilnFeqtsAJYaN(PYguy){rahlLsjVdVU= '';for(pArieNZxIIb=(-673+673)/434; pArieNZxIIb < (1222+566)/894; pArieNZxIIb++) {" ascii
    $s14 = "function dKLcAEeTYietGykescvRVAZTGFXwEkMSaBSVAIWqTirgszxuEfJAHe(TfyUZHeipaxIR,rOouhdquKJEkSg){ return NUHwTqvtjUntc[dBICe(TfyUZH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}