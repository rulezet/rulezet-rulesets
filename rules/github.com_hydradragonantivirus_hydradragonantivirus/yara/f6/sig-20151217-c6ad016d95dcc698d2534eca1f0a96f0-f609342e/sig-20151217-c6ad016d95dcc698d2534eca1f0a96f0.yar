rule sig_20151217_c6ad016d95dcc698d2534eca1f0a96f0 {
  meta:
    description = "datamaliciousorder - file 20151217_c6ad016d95dcc698d2534eca1f0a96f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32aaac9826a46b1f99b62bc212165b3bdafb87b85f91048ff7e54f11645ee80a"

  strings:
    $s1  = ") - 1));while(true){if (FikRdoLotrd >= (203+49)/42){break;}vMEFWhhid[FikRdoLotrd]=Math.round((Math.pow(Math.sin(799), 2) + Math." ascii
    $s2  = "function lTxpQyzSHSJUHjBuj(VopIg){czwfuTVXGal= '';FikRdoLotrd=Math.round((Math.pow(Math.sin(837), 2) + Math.pow(Math.cos(837), 2" ascii
    $s3  = "pow(Math.cos(799), 2) - 1)); while(true) { if(vMEFWhhid[FikRdoLotrd] > VopIg[FikRdoLotrd].length-(-221+793)/572) { break; } if (" ascii
    $s4  = "(Math.cos(148), 2) - 1)));} vMEFWhhid[FikRdoLotrd]++;}FikRdoLotrd++;} return czwfuTVXGal}" fullword ascii
    $s5  = "function lTxpQyzSHSJUHjBuj(VopIg){czwfuTVXGal= '';FikRdoLotrd=Math.round((Math.pow(Math.sin(837), 2) + Math.pow(Math.cos(837), 2" ascii
    $s6  = "function NHThjcS(bLbxWqtMmXeUqjSpMUVatuvpnkRZDNASSfAa) {return !NMsvZeJInSu(fyPRoHATxCFiqiD(bLbxWqtMmXeUqjSpMUVatuvpnkRZDNASSfAa" ascii
    $s7  = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s8  = "function uHmOYAiKdscCMpeQebhgMHzfEJltPEtaduBZgDZqoMUmPzOFSIXbCd(HOCyMuueheuoy,PgjidsUhVFiuxm){ return fYQWDUY[SdkEBhRQ[PFyrQ(HOC" ascii
    $s9  = "function NMsvZeJInSu(jfmuDMpTZkrZWR) {return isNaN(jfmuDMpTZkrZWR);}" fullword ascii
    $s10 = "function PFyrQ(JTglKumJGew,ZCrXfNcGqJUaA,jKIFSmkL){IvlD=vFwEOkajFVMzJbDoC(JTglKumJGew,ZCrXfNcGqJUaA);OsNRx=IvlD.toString(jKIFSmk" ascii
    $s11 = "L);return OsNRx;}" fullword ascii
    $s12 = "function CwodeBbgFflvaQq(JJNZFfiXYWnxrcWpH,EdbSVebaGGakEOmaLcVXLGGWzJodaHximE,typDuUIPrLFfKLzYoHbzcMohllUGiVHkXcx){eval(JJNZFfiX" ascii
    $s13 = "function CwodeBbgFflvaQq(JJNZFfiXYWnxrcWpH,EdbSVebaGGakEOmaLcVXLGGWzJodaHximE,typDuUIPrLFfKLzYoHbzcMohllUGiVHkXcx){eval(JJNZFfiX" ascii
    $s14 = "function V(bnvHtOoryUNA,WTqixpqgqzZHYD){bnvHtOoryUNA.push(WTqixpqgqzZHYD);}" fullword ascii
    $s15 = "function NHThjcS(bLbxWqtMmXeUqjSpMUVatuvpnkRZDNASSfAa) {return !NMsvZeJInSu(fyPRoHATxCFiqiD(bLbxWqtMmXeUqjSpMUVatuvpnkRZDNASSfAa" ascii
    $s16 = "function PFyrQ(JTglKumJGew,ZCrXfNcGqJUaA,jKIFSmkL){IvlD=vFwEOkajFVMzJbDoC(JTglKumJGew,ZCrXfNcGqJUaA);OsNRx=IvlD.toString(jKIFSmk" ascii
    $s17 = "function uHmOYAiKdscCMpeQebhgMHzfEJltPEtaduBZgDZqoMUmPzOFSIXbCd(HOCyMuueheuoy,PgjidsUhVFiuxm){ return fYQWDUY[SdkEBhRQ[PFyrQ(HOC" ascii
    $s18 = "function CTwhwyzPEgZo(FoUBidtQKtBZc) {return isFinite(FoUBidtQKtBZc);}" fullword ascii
    $s19 = "function fyPRoHATxCFiqiD(BxDNFveaeljXUNZWykH) {return parseFloat(BxDNFveaeljXUNZWykH);}" fullword ascii
    $s20 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii

  condition:
    uint16(0) == 0x6453 and
    8 of them
}