rule sig_20151217_3e2c2365736b097e6ed712b0314342d7 {
  meta:
    description = "datamaliciousorder - file 20151217_3e2c2365736b097e6ed712b0314342d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc7f4edac41dd838f11f2c6b480c7729c03a0e41e05ca4d3a8890eedc4707b25"

  strings:
    $s1  = "th.pow(Math.cos(404), 2) - 1)); while(true) { if(iGhAhTxzR[GrPVIIipVzQ] > GCoCx[GrPVIIipVzQ].length-(123+428)/551) { break; } if" ascii
    $s2  = "pow(Math.cos(961), 2) - 1)));} iGhAhTxzR[GrPVIIipVzQ]++;}GrPVIIipVzQ++;} return PvsEGDtaNeZ}" fullword ascii
    $s3  = "function kFAmLkPZceChygAiO(GCoCx){PvsEGDtaNeZ= '';GrPVIIipVzQ=Math.round((Math.pow(Math.sin(131), 2) + Math.pow(Math.cos(131), 2" ascii
    $s4  = ") - 1));while(true){if (GrPVIIipVzQ >= (4387+863)/875){break;}iGhAhTxzR[GrPVIIipVzQ]=Math.round((Math.pow(Math.sin(404), 2) + Ma" ascii
    $s5  = "function kFAmLkPZceChygAiO(GCoCx){PvsEGDtaNeZ= '';GrPVIIipVzQ=Math.round((Math.pow(Math.sin(131), 2) + Math.pow(Math.cos(131), 2" ascii
    $s6  = "FjrHXxsxtnElzrktHlmqspKhzusdHJbFgoX([GCoCx[GrPVIIipVzQ][iGhAhTxzR[GrPVIIipVzQ]]], Math.round((Math.pow(Math.sin(961), 2) + Math." ascii
    $s7  = "function zuFdBkW(ShzbhOaIuMoRWOdSbLtkqIwzkuRHXORcNuGj) {return !RFUePFoZMzM(NWnkfZYnTXRaAfB(ShzbhOaIuMoRWOdSbLtkqIwzkuRHXORcNuGj" ascii
    $s8  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s9  = "function i(igvbHaRtxOJCcr,reHXiHfhzXlPp,tijsgKLNoOG) {igvbHaRtxOJCcr[reHXiHfhzXlPp]=tijsgKLNoOG;}" fullword ascii
    $s10 = "function NWnkfZYnTXRaAfB(MMrWmRzoDPmkDbMQtAh) {return parseFloat(MMrWmRzoDPmkDbMQtAh);}" fullword ascii
    $s11 = "function xDBvbIWbFFgsUkswRdGFjrHXxsxtnElzrktHlmqspKhzusdHJbFgoX(oUugtORTeWcsF,VyiUUYsinWYLTs){ return qyVSMHk[CEmoHZSR[jIKJa(oUu" ascii
    $s12 = "function uXcSQsZborHwMUP(HFUnDwoIUtvFGkYlS,ImExlgUOFCtuzMuIQZElGCUCjMcSzogKDt,fBsnnXYBQigrIwoTGoxgKDEBnetNkQzCVmq){eval(HFUnDwoI" ascii
    $s13 = "function G(UIWMQNaWRYnL,RAzaIBSfSFTNJY){UIWMQNaWRYnL.push(RAzaIBSfSFTNJY);}" fullword ascii
    $s14 = "function RFUePFoZMzM(MMjIIyqRyDMXfA) {return isNaN(MMjIIyqRyDMXfA);}" fullword ascii
    $s15 = ",'V',']','C',',','>','_','Z','c','W','_','w','X','!','O','o','c','=','1','Y','E','n','Z','H','Z','N','.','m','F','[','a',String." ascii
    $s16 = "function xDBvbIWbFFgsUkswRdGFjrHXxsxtnElzrktHlmqspKhzusdHJbFgoX(oUugtORTeWcsF,VyiUUYsinWYLTs){ return qyVSMHk[CEmoHZSR[jIKJa(oUu" ascii
    $s17 = "function uXcSQsZborHwMUP(HFUnDwoIUtvFGkYlS,ImExlgUOFCtuzMuIQZElGCUCjMcSzogKDt,fBsnnXYBQigrIwoTGoxgKDEBnetNkQzCVmq){eval(HFUnDwoI" ascii
    $s18 = "function zuFdBkW(ShzbhOaIuMoRWOdSbLtkqIwzkuRHXORcNuGj) {return !RFUePFoZMzM(NWnkfZYnTXRaAfB(ShzbhOaIuMoRWOdSbLtkqIwzkuRHXORcNuGj" ascii
    $s19 = "function TgvGtsxmHhBM(lIihLVOeJGxZO) {return isFinite(lIihLVOeJGxZO);}" fullword ascii
    $s20 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4543 and
    8 of them
}