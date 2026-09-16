rule sig_20151217_7cef0440869708bad780758b3aaa4010 {
  meta:
    description = "datamaliciousorder - file 20151217_7cef0440869708bad780758b3aaa4010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c72a760fb11a08d199511c32d7ae368d17c7250271457050c427990d8ed292b5"

  strings:
    $s1  = "th.pow(Math.cos(998), 2) - 1)); while(true) { if(EgXRLGqNF[KATjFpqRyRb] > Woeas[KATjFpqRyRb].length-(423+166)/589) { break; } if" ascii
    $s2  = "function ddDIFITXMeyNMlGej(Woeas){ofazvhZFlGl= '';KATjFpqRyRb=Math.round((Math.pow(Math.sin(320), 2) + Math.pow(Math.cos(320), 2" ascii
    $s3  = "w(Math.cos(769), 2) - 1)));} EgXRLGqNF[KATjFpqRyRb]++;}KATjFpqRyRb++;} return ofazvhZFlGl}" fullword ascii
    $s4  = ") - 1));while(true){if (KATjFpqRyRb >= (2117+367)/414){break;}EgXRLGqNF[KATjFpqRyRb]=Math.round((Math.pow(Math.sin(998), 2) + Ma" ascii
    $s5  = "function ddDIFITXMeyNMlGej(Woeas){ofazvhZFlGl= '';KATjFpqRyRb=Math.round((Math.pow(Math.sin(320), 2) + Math.pow(Math.cos(320), 2" ascii
    $s6  = "function nyePGII(jqfvRwHvaqsTdodyfOIlCxmxmPCOpntpJMxU) {return !WtoIMMHKaub(lpsYnDWMDPTWaOq(jqfvRwHvaqsTdodyfOIlCxmxmPCOpntpJMxU" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "function eXQhR(YprEFWqCtTw,vQBKOnvwOnkys,yxmppFKj){WTlZ=BmzEBfNYTuQKBHubE(YprEFWqCtTw,vQBKOnvwOnkys);cyHRQ=WTlZ.toString(yxmppFK" ascii
    $s9  = "function ucpqbGICXGAW(BMdSopcrgHdkc) {return isFinite(BMdSopcrgHdkc);}" fullword ascii
    $s10 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s11 = "function E(nubIXLskVNaW,eRWBHNFgxzkmLF){nubIXLskVNaW.push(eRWBHNFgxzkmLF);}" fullword ascii
    $s12 = "function WtoIMMHKaub(fRprptQAJPjKoz) {return isNaN(fRprptQAJPjKoz);}" fullword ascii
    $s13 = "j);return cyHRQ;}" fullword ascii
    $s14 = "function nyePGII(jqfvRwHvaqsTdodyfOIlCxmxmPCOpntpJMxU) {return !WtoIMMHKaub(lpsYnDWMDPTWaOq(jqfvRwHvaqsTdodyfOIlCxmxmPCOpntpJMxU" ascii
    $s15 = "function lpsYnDWMDPTWaOq(lGHRUZSXhoPnKNsSpkd) {return parseFloat(lGHRUZSXhoPnKNsSpkd);}" fullword ascii
    $s16 = "function XCZnYMTVIREmZMVjlxHZnXaxWbjbAymHJTWrFhyEGmKirebHbwtNwJ(ufPhqZzfHGCeC,oheBMCfbdjIVzG){ return KigaXMR[ApBXWkpL[eXQhR(ufP" ascii
    $s17 = "function aThYiskVqRgOtue(UrDrTsEgujtVEArMX,EABgyifkJicdnTzLiEPPVRpILUBtHDdCyT,FVXRClIwLLeYjtloCzNORUiIyAvtcgHNANI){eval(UrDrTsEg" ascii
    $s18 = "function C(PPcuDuSWYCboAm,fOBXsbQJuDaLC,fcVUACIKFeU) {PPcuDuSWYCboAm[fOBXsbQJuDaLC]=fcVUACIKFeU;}" fullword ascii
    $s19 = "function BmzEBfNYTuQKBHubE(wNDrYnnYJF,cwdcGwVVrF) {return parseInt(wNDrYnnYJF,cwdcGwVVrF);}" fullword ascii
    $s20 = "function aThYiskVqRgOtue(UrDrTsEgujtVEArMX,EABgyifkJicdnTzLiEPPVRpILUBtHDdCyT,FVXRClIwLLeYjtloCzNORUiIyAvtcgHNANI){eval(UrDrTsEg" ascii

  condition:
    uint16(0) == 0x7041 and
    8 of them
}