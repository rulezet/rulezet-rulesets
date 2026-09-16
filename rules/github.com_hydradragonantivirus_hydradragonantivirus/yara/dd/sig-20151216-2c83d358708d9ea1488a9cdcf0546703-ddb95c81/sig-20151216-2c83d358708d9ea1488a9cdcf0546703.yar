rule sig_20151216_2c83d358708d9ea1488a9cdcf0546703 {
  meta:
    description = "datamaliciousorder - file 20151216_2c83d358708d9ea1488a9cdcf0546703.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eda9c8b177d900d3be232c6202dac2b6a8b06a0a7ce2618f4b4df2e97cdb4ac"

  strings:
    $s1  = "h.pow(Math.cos(644), 2) - 1)); while(true) { if(behjCGdOe[GVCPCTnVpYr] > ArDJU[GVCPCTnVpYr].length-(-8+958)/950) { break; } if (" ascii
    $s2  = ") - 1));while(true){if (GVCPCTnVpYr >= (5709+69)/963){break;}behjCGdOe[GVCPCTnVpYr]=Math.round((Math.pow(Math.sin(644), 2) + Mat" ascii
    $s3  = "(Math.cos(845), 2) - 1)));} behjCGdOe[GVCPCTnVpYr]++;}GVCPCTnVpYr++;} return bpsLLYrjxjl}" fullword ascii
    $s4  = "function sfioPREZAXSYmlQLj(ArDJU){bpsLLYrjxjl= '';GVCPCTnVpYr=Math.round((Math.pow(Math.sin(625), 2) + Math.pow(Math.cos(625), 2" ascii
    $s5  = "function sfioPREZAXSYmlQLj(ArDJU){bpsLLYrjxjl= '';GVCPCTnVpYr=Math.round((Math.pow(Math.sin(625), 2) + Math.pow(Math.cos(625), 2" ascii
    $s6  = "H);return MBXSO;}" fullword ascii
    $s7  = "function vLEZOOiHFVmmNIS(FladCpVzNltRfqFvAJm) {return parseFloat(FladCpVzNltRfqFvAJm);}" fullword ascii
    $s8  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s9  = "function VVXbs(vfJSnaiLtpS,bWjAEnyCvxPwD,fNVfZnAH){jUkm=fqpvGkKhOTtVKpRYC(vfJSnaiLtpS,bWjAEnyCvxPwD);MBXSO=jUkm.toString(fNVfZnA" ascii
    $s10 = "function bZJdraZGfsnJGCscctfoulLNrMggwSYVrPLqOzYRSLELYDEBjbUDVV(VqLpWlgGtMyIi,FcnnfeNitteVbi){ return FPdSntx[UKoQQTIE[VVXbs(VqL" ascii
    $s11 = "function VVXbs(vfJSnaiLtpS,bWjAEnyCvxPwD,fNVfZnAH){jUkm=fqpvGkKhOTtVKpRYC(vfJSnaiLtpS,bWjAEnyCvxPwD);MBXSO=jUkm.toString(fNVfZnA" ascii
    $s12 = "function fqpvGkKhOTtVKpRYC(KWnMOhmVnW,abxoGiYnWJ) {return parseInt(KWnMOhmVnW,abxoGiYnWJ);}" fullword ascii
    $s13 = "function OjJPcNPRvqhDhXS(yRlcrcCXbsEdxYkDE,zNKmTyLVrysBpJYshvVpEUymJApWLlcbsB,yPsYgXkRcVecLZVVqUqAioLDLvqsMVbjdCW){eval(yRlcrcCX" ascii
    $s14 = "function u(GGlQAXFEWRczJM,GZlVLUjAEZVkh,JqYajhuzrWG) {GGlQAXFEWRczJM[GZlVLUjAEZVkh]=JqYajhuzrWG;}" fullword ascii
    $s15 = "function R(WpKcZZqjIDsM,gWQBGTrxfrTcwT){WpKcZZqjIDsM.push(gWQBGTrxfrTcwT);}" fullword ascii
    $s16 = "function bZJdraZGfsnJGCscctfoulLNrMggwSYVrPLqOzYRSLELYDEBjbUDVV(VqLpWlgGtMyIi,FcnnfeNitteVbi){ return FPdSntx[UKoQQTIE[VVXbs(VqL" ascii
    $s17 = "function UtUOeifJdZmI(IwrupVFVclRvn) {return isFinite(IwrupVFVclRvn);}" fullword ascii
    $s18 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s19 = "function eTMseuDdYys(iuhtBxYQRcqdYc) {return isNaN(iuhtBxYQRcqdYc);}" fullword ascii
    $s20 = "function OjJPcNPRvqhDhXS(yRlcrcCXbsEdxYkDE,zNKmTyLVrysBpJYshvVpEUymJApWLlcbsB,yPsYgXkRcVecLZVVqUqAioLDLvqsMVbjdCW){eval(yRlcrcCX" ascii

  condition:
    uint16(0) == 0x4b55 and
    8 of them
}