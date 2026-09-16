rule sig_20160531_f41a509c97d95f44a521769562752a86 {
  meta:
    description = "datamaliciousorder - file 20160531_f41a509c97d95f44a521769562752a86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d1dc21e4a73a045dd06230f49d6b67453c619608f33c1bb213f14d7cf4e655a"

  strings:
    $s1  = "var dTeOPqK=function(){return WScript.CreateObject(QjHxGfcyLNlsECtofyev[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function hBbTDRxkVgzizTpfHuTghO(EXOTQXP,ZxRJuSlJpqBnCn){return EXOTQXP.charAt(ZxRJuSlJpqBnCn);}" fullword ascii
    $s3  = "function oEioqSiVkDWP(BtRlPsvZnKoBw) {var zYznfLMeyLKhQnyrAQtuBZa = qEjZAGIkU.join(QjHxGfcyLNlsECtofyev[7]);var CvVtRWMVJsrpd, s" ascii
    $s4  = "Txm == 64) pJWJUsfyt += Nr(CvVtRWMVJsrpd);else if (LubInKjBZGCnc == 64) pJWJUsfyt += SXCnpGzlRPhBSSUaUSpz(CvVtRWMVJsrpd, sXaUmEb" ascii
    $s5  = "function Nr(JzLFxpESiJDZdEFRhMBU){return String.fromCharCode(JzLFxpESiJDZdEFRhMBU);}" fullword ascii
    $s6  = "function UgZhPSqqVRDH(tsWSLejeH,hIABTOUPYyvOwn) {var jDzdNJnMQrMI=[QjHxGfcyLNlsECtofyev[15]];tsWSLejeH[jDzdNJnMQrMI[0]]" fullword ascii
    $s7  = "function AbVDBgGPW(){return ouvbUNgwhuQvBW(QjHxGfcyLNlsECtofyev[9],[1,5,7],QjHxGfcyLNlsECtofyev[10]);}" fullword ascii
    $s8  = "function omyUuldYqcc(){return ouvbUNgwhuQvBW(QjHxGfcyLNlsECtofyev[11],[2,4,8,10],QjHxGfcyLNlsECtofyev[12]);}" fullword ascii
    $s9  = "ngth);return pJWJUsfyt;}" fullword ascii
    $s10 = "function oEioqSiVkDWP(BtRlPsvZnKoBw) {var zYznfLMeyLKhQnyrAQtuBZa = qEjZAGIkU.join(QjHxGfcyLNlsECtofyev[7]);var CvVtRWMVJsrpd, s" ascii
    $s11 = "function HKWOUO(MAmZJ,nKxHeEoXniYVoJdlqF,lmzGBaNc){return String.fromCharCode(MAmZJ,nKxHeEoXniYVoJdlqF,lmzGBaNc);}" fullword ascii
    $s12 = "0;bWFpmKZBuAq<xvPvlmeA.length;bWFpmKZBuAq++) {cEonA+=mIBUNe[xvPvlmeA[bWFpmKZBuAq]];}return cEonA.substring(3,cEonA.length);}" fullword ascii
    $s13 = "function SXCnpGzlRPhBSSUaUSpz(OSBbdgysMbpCikgCk,BfftOniXWwmJWr){return String.fromCharCode(OSBbdgysMbpCikgCk,BfftOniXWwmJWr);}" fullword ascii
    $s14 = "bjbwauz);else pJWJUsfyt += HKWOUO(CvVtRWMVJsrpd, sXaUmEbbjbwauz, dqfRfJYLKuTleOpNTva);} while (QdDFkTEAKrpMSu < BtRlPsvZnKoBw.le" ascii
    $s15 = "function ouvbUNgwhuQvBW(RqZRbeyQo,xvPvlmeA,vsZXU){mIBUNe=RqZRbeyQo.split(vsZXU);cEonA = QjHxGfcyLNlsECtofyev[0];for(bWFpmKZBuAq=" ascii
    $s16 = "function JbHaeNha(){return ouvbUNgwhuQvBW(QjHxGfcyLNlsECtofyev[13],[0,3,6],QjHxGfcyLNlsECtofyev[14]);}" fullword ascii
    $s17 = "function ueLXZRmO(){return dTeOPqK.ExpandEnvironmentStrings(AbVDBgGPW())}" fullword ascii
    $s18 = "(KIUyNIswIAzrXo,true);oFFUAucPdISeBW.WriteLine(pbXAlU);oFFUAucPdISeBW.Close();}" fullword ascii
    $s19 = "function FvsCPsEPSu(dXqysMZgAQtqU,qSLLSgJtNvrijExVcYWalcT){return dXqysMZgAQtqU.indexOf(qSLLSgJtNvrijExVcYWalcT);}" fullword ascii
    $s20 = "function ouvbUNgwhuQvBW(RqZRbeyQo,xvPvlmeA,vsZXU){mIBUNe=RqZRbeyQo.split(vsZXU);cEonA = QjHxGfcyLNlsECtofyev[0];for(bWFpmKZBuAq=" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}