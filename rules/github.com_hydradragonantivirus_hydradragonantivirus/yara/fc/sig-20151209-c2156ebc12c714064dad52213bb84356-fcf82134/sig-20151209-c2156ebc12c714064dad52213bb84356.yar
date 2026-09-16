rule sig_20151209_c2156ebc12c714064dad52213bb84356 {
  meta:
    description = "datamaliciousorder - file 20151209_c2156ebc12c714064dad52213bb84356.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bf99eb8163fb257c5048ff806f9b1d40c9b6d4173c69b6f7929b1c7d4a34694"

  strings:
    $s1  = "function maTOgWpqlKO(tmpkflFY,ZsqsPY){return tmpkflFY.split(ZsqsPY)}" fullword ascii
    $s2  = "function FIQvHhJ(qmZgBCqgzzKFbnERJEtjyAYcJrbUthxDoTKb) {return !isNaN(parseFloat(qmZgBCqgzzKFbnERJEtjyAYcJrbUthxDoTKb)) && isFin" ascii
    $s3  = "function FIQvHhJ(qmZgBCqgzzKFbnERJEtjyAYcJrbUthxDoTKb) {return !isNaN(parseFloat(qmZgBCqgzzKFbnERJEtjyAYcJrbUthxDoTKb)) && isFin" ascii
    $s4  = "function HlacM(ZVmvvnLfZMf,QqnWpUAXPsENQ,gZHtUOXh){keWf=parseInt(ZVmvvnLfZMf,QqnWpUAXPsENQ);nCdED=keWf.toString(gZHtUOXh);return" ascii
    $s5  = "} return uHoGUaNiUHo}" fullword ascii
    $s6  = "function AgYjCyNDAstOQPDXVMpdruHyxKcHwrCKScdQECIgWAbfksUobEujnM(kBSAibCdbMbgx,otqqBZcgeOpBRF){ return Xudma[HlacM(kBSAibCdbMbgx[" ascii
    $s7  = " nCdED;}function RfervjjadtgiltS(DyTchLPmzRBRLRPCJ){eval(DyTchLPmzRBRLRPCJ)}" fullword ascii
    $s8  = "function AgYjCyNDAstOQPDXVMpdruHyxKcHwrCKScdQECIgWAbfksUobEujnM(kBSAibCdbMbgx,otqqBZcgeOpBRF){ return Xudma[HlacM(kBSAibCdbMbgx[" ascii
    $s9  = "function HlacM(ZVmvvnLfZMf,QqnWpUAXPsENQ,gZHtUOXh){keWf=parseInt(ZVmvvnLfZMf,QqnWpUAXPsENQ);nCdED=keWf.toString(gZHtUOXh);return" ascii
    $s10 = "function UHmfdQrKeJwhJhbyg(brTGc){uHoGUaNiUHo= '';for(YwuRCaqTTPg=(-212+212)/352; YwuRCaqTTPg < (896+772)/834; YwuRCaqTTPg++) {s" ascii
    $s11 = "BzfkvKvG[YwuRCaqTTPg]=(-181+181)/791; while(true) { if(sBzfkvKvG[YwuRCaqTTPg] > brTGc[YwuRCaqTTPg].length-(451+85)/536) { break;" ascii
    $s12 = "function UHmfdQrKeJwhJhbyg(brTGc){uHoGUaNiUHo= '';for(YwuRCaqTTPg=(-212+212)/352; YwuRCaqTTPg < (896+772)/834; YwuRCaqTTPg++) {s" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}