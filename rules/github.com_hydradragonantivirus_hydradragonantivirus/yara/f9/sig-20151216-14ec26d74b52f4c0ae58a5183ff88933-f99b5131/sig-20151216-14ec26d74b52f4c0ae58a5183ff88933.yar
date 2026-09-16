rule sig_20151216_14ec26d74b52f4c0ae58a5183ff88933 {
  meta:
    description = "datamaliciousorder - file 20151216_14ec26d74b52f4c0ae58a5183ff88933.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "079c8912d2990941735afa1dd385416846e994e04ffca977e359def74e7b0297"

  strings:
    $s1  = "function qkMvejcpdGlNLrobA(dZGwC){yHHlgBAyNJd= '';DahHEGfMAba=Math.round((Math.pow(Math.sin(357), 2) + Math.pow(Math.cos(357), 2" ascii
    $s2  = ") - 1));while(true){if (DahHEGfMAba >= (528+822)/225){break;}idSVhPNjN[DahHEGfMAba]=Math.round((Math.pow(Math.sin(475), 2) + Mat" ascii
    $s3  = "pow(Math.cos(451), 2) - 1)));} idSVhPNjN[DahHEGfMAba]++;}DahHEGfMAba++;} return yHHlgBAyNJd}" fullword ascii
    $s4  = "h.pow(Math.cos(475), 2) - 1)); while(true) { if(idSVhPNjN[DahHEGfMAba] > dZGwC[DahHEGfMAba].length-(-252+475)/223) { break; } if" ascii
    $s5  = "OndwlJjHkWHCbKDdLKvHrqRzYuJHlGYFJvW([dZGwC[DahHEGfMAba][idSVhPNjN[DahHEGfMAba]]], Math.round((Math.pow(Math.sin(451), 2) + Math." ascii
    $s6  = "function qkMvejcpdGlNLrobA(dZGwC){yHHlgBAyNJd= '';DahHEGfMAba=Math.round((Math.pow(Math.sin(357), 2) + Math.pow(Math.cos(357), 2" ascii
    $s7  = "function AQVayelNsgQYQswniybOndwlJjHkWHCbKDdLKvHrqRzYuJHlGYFJvW(LBdfdIKEyveOA,GWXRNFeocRmRjJ){ return pXNWmJc[fLaZXnzo[COjKY(LBd" ascii
    $s8  = "function AQVayelNsgQYQswniybOndwlJjHkWHCbKDdLKvHrqRzYuJHlGYFJvW(LBdfdIKEyveOA,GWXRNFeocRmRjJ){ return pXNWmJc[fLaZXnzo[COjKY(LBd" ascii
    $s9  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s10 = "function DbePfZdEyoo(zFEoXqsTWXwbPO) {return isNaN(zFEoXqsTWXwbPO);}" fullword ascii
    $s11 = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s12 = "function GfiqeJslSBfq(DOojyJFJVGQgV) {return isFinite(DOojyJFJVGQgV);}" fullword ascii
    $s13 = "S);return dsigp;}" fullword ascii
    $s14 = "function s(QIasyKSNDcPk,RQpnFnmKfadjst){QIasyKSNDcPk.push(RQpnFnmKfadjst);}" fullword ascii
    $s15 = "function E(abBrhHEooydSmT,aNlTcwpoFNSWu,ENArYFKCiWW) {abBrhHEooydSmT[aNlTcwpoFNSWu]=ENArYFKCiWW;}" fullword ascii
    $s16 = "function FtlVZZr(tAzeLExIVmnftvpuOnIXQsrudoOAzQNVIekx) {return !DbePfZdEyoo(ZYdZuhzCaJNQHjI(tAzeLExIVmnftvpuOnIXQsrudoOAzQNVIekx" ascii
    $s17 = "function hyRtOUhXQEnbcaLQQ(ZLSIClhfbv,GabfCZJUhX) {return parseInt(ZLSIClhfbv,GabfCZJUhX);}" fullword ascii
    $s18 = "function COjKY(OZryORJpcdz,WOlmSzgMFgedH,ZCUQcXxS){ZEhj=hyRtOUhXQEnbcaLQQ(OZryORJpcdz,WOlmSzgMFgedH);dsigp=ZEhj.toString(ZCUQcXx" ascii
    $s19 = "function COjKY(OZryORJpcdz,WOlmSzgMFgedH,ZCUQcXxS){ZEhj=hyRtOUhXQEnbcaLQQ(OZryORJpcdz,WOlmSzgMFgedH);dsigp=ZEhj.toString(ZCUQcXx" ascii
    $s20 = "function ZYdZuhzCaJNQHjI(SRDqqJnwUsdAFbhArxH) {return parseFloat(SRDqqJnwUsdAFbhArxH);}" fullword ascii

  condition:
    uint16(0) == 0x4c66 and
    8 of them
}