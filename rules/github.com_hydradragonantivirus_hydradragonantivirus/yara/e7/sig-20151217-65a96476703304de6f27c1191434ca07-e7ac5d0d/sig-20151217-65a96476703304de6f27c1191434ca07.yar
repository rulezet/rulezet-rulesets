rule sig_20151217_65a96476703304de6f27c1191434ca07 {
  meta:
    description = "datamaliciousorder - file 20151217_65a96476703304de6f27c1191434ca07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "139bb8d46b4ad524451951cdf013cbd1526440c8ee693f8ba500f326b63ce049"

  strings:
    $s1  = "function ggqKgTBXuniOypJFr(HYfsF){rogNXhxYYjQ= '';TXQglTKIksq=Math.round((Math.pow(Math.sin(638), 2) + Math.pow(Math.cos(638), 2" ascii
    $s2  = ") - 1));while(true){if (TXQglTKIksq >= (2576+406)/497){break;}ALNZBHBur[TXQglTKIksq]=Math.round((Math.pow(Math.sin(479), 2) + Ma" ascii
    $s3  = ".pow(Math.cos(337), 2) - 1)));} ALNZBHBur[TXQglTKIksq]++;}TXQglTKIksq++;} return rogNXhxYYjQ}" fullword ascii
    $s4  = "th.pow(Math.cos(479), 2) - 1)); while(true) { if(ALNZBHBur[TXQglTKIksq] > HYfsF[TXQglTKIksq].length-(-270+559)/289) { break; } i" ascii
    $s5  = "function ggqKgTBXuniOypJFr(HYfsF){rogNXhxYYjQ= '';TXQglTKIksq=Math.round((Math.pow(Math.sin(638), 2) + Math.pow(Math.cos(638), 2" ascii
    $s6  = "wTFCsKLhPVKdRlzNjtpJcBKFiUjLIZfBmolu([HYfsF[TXQglTKIksq][ALNZBHBur[TXQglTKIksq]]], Math.round((Math.pow(Math.sin(337), 2) + Math" ascii
    $s7  = "function dhlyIFE(OgtlsuhcbhFRTyDwvTSnweyXwipCnMJFzVbT) {return !xcXcrugSKmK(ydWeoDXrlugngJC(OgtlsuhcbhFRTyDwvTSnweyXwipCnMJFzVbT" ascii
    $s8  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s9  = "function QfUzzZLvVqRPzwlrSawTFCsKLhPVKdRlzNjtpJcBKFiUjLIZfBmolu(xRXXKYQsLixZN,okXbXQSCgvGzlL){ return WCrpMJR[ITJKCfFn[zscLH(xRX" ascii
    $s10 = "function UsBwPOQzSYPw(deiDrSrdcRwTg) {return isFinite(deiDrSrdcRwTg);}" fullword ascii
    $s11 = "function ydWeoDXrlugngJC(bpLdNHWgdwLnVUCcprW) {return parseFloat(bpLdNHWgdwLnVUCcprW);}" fullword ascii
    $s12 = "function QnVvZQZPnJTdrSgJK(GwFFVGRKZC,lGGXGjdNLd) {return parseInt(GwFFVGRKZC,lGGXGjdNLd);}" fullword ascii
    $s13 = "function u(NfsiFITDcYlr,DvJfvjtEVVECut){NfsiFITDcYlr.push(DvJfvjtEVVECut);}" fullword ascii
    $s14 = "function PsgdTLLbSjyPByn(wFVGqKQZAqtfMBBiI,TMncWgGAGzEZVSgYCENCmHtYxALSETgYSa,syGZnkLOCnhjfQxZaqytoTQtSFkiUtFvlEZ){eval(wFVGqKQZ" ascii
    $s15 = "function PsgdTLLbSjyPByn(wFVGqKQZAqtfMBBiI,TMncWgGAGzEZVSgYCENCmHtYxALSETgYSa,syGZnkLOCnhjfQxZaqytoTQtSFkiUtFvlEZ){eval(wFVGqKQZ" ascii
    $s16 = "function zscLH(ANvVBpGZblx,vLezELLPqaHwX,jYoFgeqk){EaRo=QnVvZQZPnJTdrSgJK(ANvVBpGZblx,vLezELLPqaHwX);fMyJz=EaRo.toString(jYoFgeq" ascii
    $s17 = "function xcXcrugSKmK(qZSUKHdLpGjZHc) {return isNaN(qZSUKHdLpGjZHc);}" fullword ascii
    $s18 = "function QfUzzZLvVqRPzwlrSawTFCsKLhPVKdRlzNjtpJcBKFiUjLIZfBmolu(xRXXKYQsLixZN,okXbXQSCgvGzlL){ return WCrpMJR[ITJKCfFn[zscLH(xRX" ascii
    $s19 = "function dhlyIFE(OgtlsuhcbhFRTyDwvTSnweyXwipCnMJFzVbT) {return !xcXcrugSKmK(ydWeoDXrlugngJC(OgtlsuhcbhFRTyDwvTSnweyXwipCnMJFzVbT" ascii
    $s20 = "function v(rdZvbYqqZoghbe,bSzxZYaHEgmvk,bpuVMQoEfwb) {rdZvbYqqZoghbe[bSzxZYaHEgmvk]=bpuVMQoEfwb;}" fullword ascii

  condition:
    uint16(0) == 0x5449 and
    8 of them
}