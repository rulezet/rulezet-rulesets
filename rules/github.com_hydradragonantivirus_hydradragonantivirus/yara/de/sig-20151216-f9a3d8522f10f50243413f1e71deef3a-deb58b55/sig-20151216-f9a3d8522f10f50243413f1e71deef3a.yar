rule sig_20151216_f9a3d8522f10f50243413f1e71deef3a {
  meta:
    description = "datamaliciousorder - file 20151216_f9a3d8522f10f50243413f1e71deef3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e04fd3fbfe2aac3e62ce55a4f74bd2503a45825ea43d8ecba923a5b88166bc"

  strings:
    $s1  = ") - 1));while(true){if (KMjixqwwuvm >= (1934+358)/382){break;}kDLANZNYf[KMjixqwwuvm]=Math.round((Math.pow(Math.sin(846), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(846), 2) - 1)); while(true) { if(kDLANZNYf[KMjixqwwuvm] > QGSEz[KMjixqwwuvm].length-(-322+499)/177) { break; } i" ascii
    $s3  = ".pow(Math.cos(199), 2) - 1)));} kDLANZNYf[KMjixqwwuvm]++;}KMjixqwwuvm++;} return WYBxBocAAzl}" fullword ascii
    $s4  = "function qemuPnTfoHtHDTqMq(QGSEz){WYBxBocAAzl= '';KMjixqwwuvm=Math.round((Math.pow(Math.sin(541), 2) + Math.pow(Math.cos(541), 2" ascii
    $s5  = "DvwgyXqjHBvnLBTmsaJXodcPPbJkddvNFlTG([QGSEz[KMjixqwwuvm][kDLANZNYf[KMjixqwwuvm]]], Math.round((Math.pow(Math.sin(199), 2) + Math" ascii
    $s6  = "function qemuPnTfoHtHDTqMq(QGSEz){WYBxBocAAzl= '';KMjixqwwuvm=Math.round((Math.pow(Math.sin(541), 2) + Math.pow(Math.cos(541), 2" ascii
    $s7  = "function FHEvSmI(gVVmVtIiaqBQsxklIuxpUngUmNwsZdmHEDnS) {return !SDsvESQSVyI(eRnvYvVuWCJYgtm(gVVmVtIiaqBQsxklIuxpUngUmNwsZdmHEDnS" ascii
    $s8  = "function PYWQRwuPShxpelPaA(YxCMqPhgTa,wGtMAfsVdk) {return parseInt(YxCMqPhgTa,wGtMAfsVdk);}" fullword ascii
    $s9  = "function ZfNEb(uSGTFixaEUI,swSYHnxoPVxjE,wJmiJQmN){NkXv=PYWQRwuPShxpelPaA(uSGTFixaEUI,swSYHnxoPVxjE);bOeGK=NkXv.toString(wJmiJQm" ascii
    $s10 = "function PJEPfTLhVkDUIwLsvDDvwgyXqjHBvnLBTmsaJXodcPPbJkddvNFlTG(HvNUedvZJGxjI,wdPxYFOYvFxirX){ return CsJPlUs[ggGtLFfI[ZfNEb(HvN" ascii
    $s11 = "function FHEvSmI(gVVmVtIiaqBQsxklIuxpUngUmNwsZdmHEDnS) {return !SDsvESQSVyI(eRnvYvVuWCJYgtm(gVVmVtIiaqBQsxklIuxpUngUmNwsZdmHEDnS" ascii
    $s12 = "function CeEmcutQWnVg(MokkJjSpXOOer) {return isFinite(MokkJjSpXOOer);}" fullword ascii
    $s13 = "function PJEPfTLhVkDUIwLsvDDvwgyXqjHBvnLBTmsaJXodcPPbJkddvNFlTG(HvNUedvZJGxjI,wdPxYFOYvFxirX){ return CsJPlUs[ggGtLFfI[ZfNEb(HvN" ascii
    $s14 = "function A(qBnDPdKdpSjV,udqAROMbwRrLrK){qBnDPdKdpSjV.push(udqAROMbwRrLrK);}" fullword ascii
    $s15 = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s16 = "function oJutWcpTWUdzPwd(fVZdsEOztidyItzGP,COrFbrvDPnoPwDxzBBNuXIPTnjJFRhAPiA,QLFtUdppiTzGfsByHSouTmDpjuunUXTKTAK){eval(fVZdsEOz" ascii
    $s17 = "function SDsvESQSVyI(BMKVfNqOXiNPAb) {return isNaN(BMKVfNqOXiNPAb);}" fullword ascii
    $s18 = "function eRnvYvVuWCJYgtm(ESZVpzlOpvTWbOOMpQo) {return parseFloat(ESZVpzlOpvTWbOOMpQo);}" fullword ascii
    $s19 = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s20 = "function Y(uZXQFxqqKosIRq,uJnMlnDhLjABg,CraBgbtfIsI) {uZXQFxqqKosIRq[uJnMlnDhLjABg]=CraBgbtfIsI;}" fullword ascii

  condition:
    uint16(0) == 0x6767 and
    8 of them
}