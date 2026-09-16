rule sig_20151217_5a1216ce7fe9edc728b772b0d5f05324 {
  meta:
    description = "datamaliciousorder - file 20151217_5a1216ce7fe9edc728b772b0d5f05324.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6abda48524de862a408a21b396d85dc3566e8a4343d35ceda7d9e0266b6faf93"

  strings:
    $s1  = "function FvKBFhdqNXArozWbh(fzqDA){UlygmPThlEp= '';CSDGrageLMt=Math.round((Math.pow(Math.sin(185), 2) + Math.pow(Math.cos(185), 2" ascii
    $s2  = "AwAaPNGnWBIDgqhLbiVspYfDSWkAOyLCJim([fzqDA[CSDGrageLMt][ekgHAiwRu[CSDGrageLMt]]], Math.round((Math.pow(Math.sin(957), 2) + Math." ascii
    $s3  = "th.pow(Math.cos(116), 2) - 1)); while(true) { if(ekgHAiwRu[CSDGrageLMt] > fzqDA[CSDGrageLMt].length-(182+615)/797) { break; } if" ascii
    $s4  = ") - 1));while(true){if (CSDGrageLMt >= (5101+275)/896){break;}ekgHAiwRu[CSDGrageLMt]=Math.round((Math.pow(Math.sin(116), 2) + Ma" ascii
    $s5  = "pow(Math.cos(957), 2) - 1)));} ekgHAiwRu[CSDGrageLMt]++;}CSDGrageLMt++;} return UlygmPThlEp}" fullword ascii
    $s6  = "function jJKDLTeUTMpAvrJzeMSAwAaPNGnWBIDgqhLbiVspYfDSWkAOyLCJim(sEZVdpLruVWiE,lwGvrVjgaolZZd){ return sZfcWeF[fTnSPEXo[daSUc(sEZ" ascii
    $s7  = "function jJKDLTeUTMpAvrJzeMSAwAaPNGnWBIDgqhLbiVspYfDSWkAOyLCJim(sEZVdpLruVWiE,lwGvrVjgaolZZd){ return sZfcWeF[fTnSPEXo[daSUc(sEZ" ascii
    $s8  = "function FvKBFhdqNXArozWbh(fzqDA){UlygmPThlEp= '';CSDGrageLMt=Math.round((Math.pow(Math.sin(185), 2) + Math.pow(Math.cos(185), 2" ascii
    $s9  = "function qjWnpXN(fJjzXJRkiwUbvuDuKlablPUxnBsukWEhHvoj) {return !DZDgosOQdVw(XndxmivhSGwNlnj(fJjzXJRkiwUbvuDuKlablPUxnBsukWEhHvoj" ascii
    $s10 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s11 = "function SvfwcDjDJqJGcEE(zyDpIsBIGpxJsJrXQ,KxMSArzPgNKgUYrqfroNrdkaEAkvQiDIza,qRksvIktMKaqwmwYKCWydblLfOHGjyuYdfv){eval(zyDpIsBI" ascii
    $s12 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s13 = "function DZDgosOQdVw(hEHiaygpqBvcjW) {return isNaN(hEHiaygpqBvcjW);}" fullword ascii
    $s14 = "function qjWnpXN(fJjzXJRkiwUbvuDuKlablPUxnBsukWEhHvoj) {return !DZDgosOQdVw(XndxmivhSGwNlnj(fJjzXJRkiwUbvuDuKlablPUxnBsukWEhHvoj" ascii
    $s15 = "function x(HtFdIRQEWOZl,SdaQZyjmVBXCtU){HtFdIRQEWOZl.push(SdaQZyjmVBXCtU);}" fullword ascii
    $s16 = "function XndxmivhSGwNlnj(qncXslVUEybYJMUikkU) {return parseFloat(qncXslVUEybYJMUikkU);}" fullword ascii
    $s17 = "function z(vGztXawnvGJsRP,SAreYopTzaPtD,mJLBAPgZMDj) {vGztXawnvGJsRP[SAreYopTzaPtD]=mJLBAPgZMDj;}" fullword ascii
    $s18 = "function SvfwcDjDJqJGcEE(zyDpIsBIGpxJsJrXQ,KxMSArzPgNKgUYrqfroNrdkaEAkvQiDIza,qRksvIktMKaqwmwYKCWydblLfOHGjyuYdfv){eval(zyDpIsBI" ascii
    $s19 = "function SMWfyhzFZPRV(JMKlCslMkBNEd) {return isFinite(JMKlCslMkBNEd);}" fullword ascii
    $s20 = "G);return MVMtp;}" fullword ascii

  condition:
    uint16(0) == 0x5466 and
    8 of them
}