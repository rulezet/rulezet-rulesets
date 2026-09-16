rule sig_20160531_d0d0e4bd7068c7ce16e06d76a52a7bd7 {
  meta:
    description = "datamaliciousorder - file 20160531_d0d0e4bd7068c7ce16e06d76a52a7bd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "556f3702a5738da40d7cf7084c91ebef02c152a8dd37bd0a1117db175684613d"

  strings:
    $s1  = "var rzlQyrvDuv=function(){return WScript.CreateObject(MdabrawSfeZpZkuPKsFH[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mgMPBYjXKwRnuLucbKHcMErt(JZakBCYVhLXL,tkuRpuAvWGccKhyfxUFnfcLs){return JZakBCYVhLXL.charAt(tkuRpuAvWGccKhyfxUFnfcLs);}" fullword ascii
    $s3  = "pr);else if (HQnBWyxcomdZzcfOczJQM == 64) DKTtOMKGRHIaeWWCmmNFNxcE += vrLPmAoXrUXjwNruERxF(DuqyVpr, goywPQsyRPSmaAPYBU);else DKT" ascii
    $s4  = "YPCfetquFtT.length;lQBqDrO++) {PDGUEkUBmtEf+=DXsKB[YPCfetquFtT[lQBqDrO]];}return PDGUEkUBmtEf.substring(3,PDGUEkUBmtEf.length);}" ascii
    $s5  = "function vrLPmAoXrUXjwNruERxF(ohmFPopNaAyQnew,YIFldvmhkHvhgAVwPXNI){return String.fromCharCode(ohmFPopNaAyQnew,YIFldvmhkHvhgAVwP" ascii
    $s6  = "function tSLHpYxqfrGvnO(lFOJDC,zItddeCcU) {var VNEhv=[MdabrawSfeZpZkuPKsFH[15]];lFOJDC[VNEhv[0]]" fullword ascii
    $s7  = "var yYSrTDDPLKN=function(){return new ActiveXObject(MdabrawSfeZpZkuPKsFH[1]);}();" fullword ascii
    $s8  = "function pXwbk(){return rzlQyrvDuv.ExpandEnvironmentStrings(RhSplwTc())}" fullword ascii
    $s9  = "function SIjyNMCYwmmWM(){return eVDIdCt(MdabrawSfeZpZkuPKsFH[13],[0,3,6],MdabrawSfeZpZkuPKsFH[14]);}" fullword ascii
    $s10 = "(zItddeCcU,0x1,0x0)}function XsQMEDOij(DkpnzyjmrPp,PJXmieb,sQEUTXgYHbV){var OJIOMYbrWwbkUO=DkpnzyjmrPp.createtextfile(PJXmieb,tr" ascii
    $s11 = "function qq(kOWtth){return String.fromCharCode(kOWtth);}" fullword ascii
    $s12 = "function RhSplwTc(){return eVDIdCt(MdabrawSfeZpZkuPKsFH[9],[1,5,7],MdabrawSfeZpZkuPKsFH[10]);}" fullword ascii
    $s13 = "function mQuUxZbiCwYUnRkPWhNeGSps(mHSjv,HDVgcXySLwXGTjFswUZciL){return mHSjv.indexOf(HDVgcXySLwXGTjFswUZciL);}" fullword ascii
    $s14 = "(zItddeCcU,0x1,0x0)}function XsQMEDOij(DkpnzyjmrPp,PJXmieb,sQEUTXgYHbV){var OJIOMYbrWwbkUO=DkpnzyjmrPp.createtextfile(PJXmieb,tr" ascii
    $s15 = "ngth);return DKTtOMKGRHIaeWWCmmNFNxcE;}" fullword ascii
    $s16 = "function eVDIdCt(EeqNB,YPCfetquFtT,OMoaH){DXsKB=EeqNB.split(OMoaH);PDGUEkUBmtEf = MdabrawSfeZpZkuPKsFH[0];for(lQBqDrO=0;lQBqDrO<" ascii
    $s17 = "function gOmTITKG(nFSCMMJFtwbdFIkOPxvbNZ,niBFBbXNxAJNyIRYRz,gDArcKFjIKaESdyZSkInXdjf){return String.fromCharCode(nFSCMMJFtwbdFIk" ascii
    $s18 = "function GhgVwiyFu(RibwpSgGekYsj) {var ABcprgAh = MzRKjEybCklApSKpkqMmMv.join(MdabrawSfeZpZkuPKsFH[7]);var DuqyVpr, goywPQsyRPSm" ascii
    $s19 = "function vrLPmAoXrUXjwNruERxF(ohmFPopNaAyQnew,YIFldvmhkHvhgAVwPXNI){return String.fromCharCode(ohmFPopNaAyQnew,YIFldvmhkHvhgAVwP" ascii
    $s20 = "function nXHvXYqLwuQB(){return eVDIdCt(MdabrawSfeZpZkuPKsFH[11],[2,4,8,10],MdabrawSfeZpZkuPKsFH[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}