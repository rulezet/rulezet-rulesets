rule sig_20151211_232e28617ea73d7c217342ce637c8567 {
  meta:
    description = "datamaliciousorder - file 20151211_232e28617ea73d7c217342ce637c8567.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bdafcef4026fa63672c6bd30d601f318faa5026e4259574982cb7bfc5e9131f"

  strings:
    $s1  = "function JRGwQke(zjMOrRgWcuOEAojBCDPDznwVzMTLHbyXjToc) {return !isNaN(parseFloat(zjMOrRgWcuOEAojBCDPDznwVzMTLHbyXjToc)) && isFin" ascii
    $s2  = "function JRGwQke(zjMOrRgWcuOEAojBCDPDznwVzMTLHbyXjToc) {return !isNaN(parseFloat(zjMOrRgWcuOEAojBCDPDznwVzMTLHbyXjToc)) && isFin" ascii
    $s3  = "var f=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"54\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "LFDTdyT[JfoCYtkIyMH]=(-404+404)/720; while(true) { if(cWLFDTdyT[JfoCYtkIyMH] > uwWem[JfoCYtkIyMH].length-(-400+465)/65) { break;" ascii
    $s5  = "function XuRxF(AgRiwrVwjrS,HPRZFWXTOrUSH,BGUYyIZB){jGKe=parseInt(AgRiwrVwjrS,HPRZFWXTOrUSH);wsHhg=jGKe.toString(BGUYyIZB);return" ascii
    $s6  = "var f=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"54\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = " wsHhg;}function xanEUTDxLwJXfUW(cFzjFRTPvcnzVatYZ){eval(cFzjFRTPvcnzVatYZ)}" fullword ascii
    $s8  = "var q=new Array(\"28\",\"2e\",\"2d\",\"2d\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s9  = "function pWBRTtvEyrHJYbEbM(uwWem){gtpvZXOcboU= '';JfoCYtkIyMH=(-769+769)/56; while(true){if(JfoCYtkIyMH >= (-86+176)/45)break;cW" ascii
    $s10 = "function XuRxF(AgRiwrVwjrS,HPRZFWXTOrUSH,BGUYyIZB){jGKe=parseInt(AgRiwrVwjrS,HPRZFWXTOrUSH);wsHhg=jGKe.toString(BGUYyIZB);return" ascii
    $s11 = "var q=new Array(\"28\",\"2e\",\"2d\",\"2d\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s12 = "function dkczyKnNkqqOyyIBZjkvQXPJVsLMMiRpdeRgAVapQRVllGlSZsmvzy(uxjeISSfPiItq,ahfeeBFRylcgZr){ return wSyty[XuRxF(uxjeISSfPiItq[" ascii
    $s13 = "function dkczyKnNkqqOyyIBZjkvQXPJVsLMMiRpdeRgAVapQRVllGlSZsmvzy(uxjeISSfPiItq,ahfeeBFRylcgZr){ return wSyty[XuRxF(uxjeISSfPiItq[" ascii
    $s14 = "+;}JfoCYtkIyMH++;} return gtpvZXOcboU}" fullword ascii
    $s15 = "function gADHuQJuaAf(nghDkBZZ,WAItZj){return nghDkBZZ.split(WAItZj)}" fullword ascii
    $s16 = "function pWBRTtvEyrHJYbEbM(uwWem){gtpvZXOcboU= '';JfoCYtkIyMH=(-769+769)/56; while(true){if(JfoCYtkIyMH >= (-86+176)/45)break;cW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}