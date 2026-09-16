rule sig_20151217_2c33a5e99f06d3a3ff6ad514a87499f5 {
  meta:
    description = "datamaliciousorder - file 20151217_2c33a5e99f06d3a3ff6ad514a87499f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d38ea54110be9cffbf06f0cbae26d9aecb5f5de5148e615af4aa4fa243012ae"

  strings:
    $s1  = "w(Math.cos(793), 2) - 1)));} LRRfTsJbl[bZnAcWlmVlH]++;}bZnAcWlmVlH++;} return HQOzNNWOAgc}" fullword ascii
    $s2  = "th.pow(Math.cos(772), 2) - 1)); while(true) { if(LRRfTsJbl[bZnAcWlmVlH] > YCRwp[bZnAcWlmVlH].length-(310+341)/651) { break; } if" ascii
    $s3  = ") - 1));while(true){if (bZnAcWlmVlH >= (4099+335)/739){break;}LRRfTsJbl[bZnAcWlmVlH]=Math.round((Math.pow(Math.sin(772), 2) + Ma" ascii
    $s4  = "function vcWvwPFLQYCdLRQwk(YCRwp){HQOzNNWOAgc= '';bZnAcWlmVlH=Math.round((Math.pow(Math.sin(473), 2) + Math.pow(Math.cos(473), 2" ascii
    $s5  = "function vcWvwPFLQYCdLRQwk(YCRwp){HQOzNNWOAgc= '';bZnAcWlmVlH=Math.round((Math.pow(Math.sin(473), 2) + Math.pow(Math.cos(473), 2" ascii
    $s6  = "function CNSgdvD(feiOqMEXFvBiMjrVsAYQPepLYBtLUuTYegvO) {return !XbljJFDNmFA(uERAoFPbWTrynys(feiOqMEXFvBiMjrVsAYQPepLYBtLUuTYegvO" ascii
    $s7  = "function ldmAoVNvexOmqPr(CdtOojMkmAcOfvLAF,ZgAmPKDXobyAHBAPBanfMSOndoMFDnHWdx,cOjzDZTJsLzNFKXwJdiNwzvuhgntRtExFWT){eval(CdtOojMk" ascii
    $s8  = "N);return thBRX;}" fullword ascii
    $s9  = "function pFWUDrQFRkLBBmAsq(KbLcJyuUOS,iuNUPHvlxd) {return parseInt(KbLcJyuUOS,iuNUPHvlxd);}" fullword ascii
    $s10 = "function h(vMzbRbpuKIue,HqheUFOtPTShVp){vMzbRbpuKIue.push(HqheUFOtPTShVp);}" fullword ascii
    $s11 = "function uERAoFPbWTrynys(jPTgmIsjJutXHRVxhQd) {return parseFloat(jPTgmIsjJutXHRVxhQd);}" fullword ascii
    $s12 = ",'k','a','*','V','^','W','3',']','+','L','7','k','X','Q','a','8','D','Y','H','3','4','Z','x','P','+','y','[','@','R','A',String." ascii
    $s13 = "function PLdkDjZdAuwx(gMDCcYSAdfzeV) {return isFinite(gMDCcYSAdfzeV);}" fullword ascii
    $s14 = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s15 = "function ihnyfwhgbuQAUSbrkqnHlGYUDSTVHgRQmnukcwnwXdjftNfrIoSZcU(qlodzcgBiCexM,FjaJjxYPUbAWRL){ return iwsUuTW[jgEaMnxz[tfxJa(qlo" ascii
    $s16 = "function ihnyfwhgbuQAUSbrkqnHlGYUDSTVHgRQmnukcwnwXdjftNfrIoSZcU(qlodzcgBiCexM,FjaJjxYPUbAWRL){ return iwsUuTW[jgEaMnxz[tfxJa(qlo" ascii
    $s17 = "function tfxJa(HrGDGZwuEfM,BLebDkwuUVWGC,DaKjScZN){qlCW=pFWUDrQFRkLBBmAsq(HrGDGZwuEfM,BLebDkwuUVWGC);thBRX=qlCW.toString(DaKjScZ" ascii
    $s18 = "function w(TGPxplayZzYmmt,wPsDupDofnYNU,saIpTaHAlrJ) {TGPxplayZzYmmt[wPsDupDofnYNU]=saIpTaHAlrJ;}" fullword ascii
    $s19 = "function tfxJa(HrGDGZwuEfM,BLebDkwuUVWGC,DaKjScZN){qlCW=pFWUDrQFRkLBBmAsq(HrGDGZwuEfM,BLebDkwuUVWGC);thBRX=qlCW.toString(DaKjScZ" ascii
    $s20 = "function XbljJFDNmFA(qlGcSjqPMAvZhU) {return isNaN(qlGcSjqPMAvZhU);}" fullword ascii

  condition:
    uint16(0) == 0x676a and
    8 of them
}