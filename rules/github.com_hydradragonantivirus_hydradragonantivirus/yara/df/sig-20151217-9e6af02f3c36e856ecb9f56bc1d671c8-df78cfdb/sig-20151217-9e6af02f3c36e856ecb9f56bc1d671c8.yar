rule sig_20151217_9e6af02f3c36e856ecb9f56bc1d671c8 {
  meta:
    description = "datamaliciousorder - file 20151217_9e6af02f3c36e856ecb9f56bc1d671c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62874ab5b337734e9b8251b8ef3a6c97bc82968cfaacd73a33b627802ceb78f0"

  strings:
    $s1  = "w(Math.cos(498), 2) - 1)));} xLyfKphHR[vbbYFAQcmRC]++;}vbbYFAQcmRC++;} return icClGOiZtRL}" fullword ascii
    $s2  = "h.pow(Math.cos(62), 2) - 1)); while(true) { if(xLyfKphHR[vbbYFAQcmRC] > sDUDI[vbbYFAQcmRC].length-(403+556)/959) { break; } if (" ascii
    $s3  = ") - 1));while(true){if (vbbYFAQcmRC >= (2823+429)/542){break;}xLyfKphHR[vbbYFAQcmRC]=Math.round((Math.pow(Math.sin(62), 2) + Mat" ascii
    $s4  = "function ZzVUbawjrvzdclJjW(sDUDI){icClGOiZtRL= '';vbbYFAQcmRC=Math.round((Math.pow(Math.sin(820), 2) + Math.pow(Math.cos(820), 2" ascii
    $s5  = "function ZzVUbawjrvzdclJjW(sDUDI){icClGOiZtRL= '';vbbYFAQcmRC=Math.round((Math.pow(Math.sin(820), 2) + Math.pow(Math.cos(820), 2" ascii
    $s6  = "function PbTsNJy(zIRUPzOqhDUISnTlTFzqzCNHGbdgdrEqyNYY) {return !JDiWMjKMHDc(PRlayyXOMXbZVLC(zIRUPzOqhDUISnTlTFzqzCNHGbdgdrEqyNYY" ascii
    $s7  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s8  = "function pdjGXCtOaxSi(dUzkyGUUiHmOl) {return isFinite(dUzkyGUUiHmOl);}" fullword ascii
    $s9  = "function jaxPCGwKiGvQMDywBQlhRCJdwefqmjlHQaBfJyQPxYvDMdVGtanGxT(kAqjJXPdFcvSC,BDiHrxrAcROqqy){ return zQSwhhX[hPRxIrXU[lzUtN(kAq" ascii
    $s10 = "function SylHChfZOIrwgbC(ZSAFMxybbJsAkZmRL,bybSoEOfRucKDnkSuYNOZMLMibJdJvZuAI,WyxyCRJoDdSDAUSiUVaodnNjPediMYoZhHh){eval(ZSAFMxyb" ascii
    $s11 = "function PbTsNJy(zIRUPzOqhDUISnTlTFzqzCNHGbdgdrEqyNYY) {return !JDiWMjKMHDc(PRlayyXOMXbZVLC(zIRUPzOqhDUISnTlTFzqzCNHGbdgdrEqyNYY" ascii
    $s12 = "N);return nGMJT;}" fullword ascii
    $s13 = "function n(gkfzAHHolrEA,qIbTgHeSsrLHPn){gkfzAHHolrEA.push(qIbTgHeSsrLHPn);}" fullword ascii
    $s14 = "function JDiWMjKMHDc(qyIMyMRPESjbDb) {return isNaN(qyIMyMRPESjbDb);}" fullword ascii
    $s15 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s16 = ",' ','n','V','H','X','_','t','W','8','X','{','#','[','x','Y','F','s','I','G','Z','!','(','=','$','6',')','j','[','S','r',String." ascii
    $s17 = "function jaxPCGwKiGvQMDywBQlhRCJdwefqmjlHQaBfJyQPxYvDMdVGtanGxT(kAqjJXPdFcvSC,BDiHrxrAcROqqy){ return zQSwhhX[hPRxIrXU[lzUtN(kAq" ascii
    $s18 = "function SylHChfZOIrwgbC(ZSAFMxybbJsAkZmRL,bybSoEOfRucKDnkSuYNOZMLMibJdJvZuAI,WyxyCRJoDdSDAUSiUVaodnNjPediMYoZhHh){eval(ZSAFMxyb" ascii
    $s19 = "function g(xKCyphmZTwQxLP,ENcqHXjliGbpm,pPDUEPPOBfA) {xKCyphmZTwQxLP[ENcqHXjliGbpm]=pPDUEPPOBfA;}" fullword ascii
    $s20 = "function PRlayyXOMXbZVLC(emnbUBNWdftrQBeonUJ) {return parseFloat(emnbUBNWdftrQBeonUJ);}" fullword ascii

  condition:
    uint16(0) == 0x5068 and
    8 of them
}