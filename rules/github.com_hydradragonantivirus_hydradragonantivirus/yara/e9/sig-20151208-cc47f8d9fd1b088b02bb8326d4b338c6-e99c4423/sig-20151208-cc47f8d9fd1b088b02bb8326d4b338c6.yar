rule sig_20151208_cc47f8d9fd1b088b02bb8326d4b338c6 {
  meta:
    description = "datamaliciousorder - file 20151208_cc47f8d9fd1b088b02bb8326d4b338c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9515552c2863b9153c0b4ff2bca2ac6538b1556bc1621026560b3cd39b8cc05b"

  strings:
    $s1  = "function SBqWOWj(CcpnUJoNLPEinYOyBbMRCrUTDAkIEFtLlHeZ) {return !isNaN(parseFloat(CcpnUJoNLPEinYOyBbMRCrUTDAkIEFtLlHeZ)) && isFin" ascii
    $s2  = "function SBqWOWj(CcpnUJoNLPEinYOyBbMRCrUTDAkIEFtLlHeZ) {return !isNaN(parseFloat(CcpnUJoNLPEinYOyBbMRCrUTDAkIEFtLlHeZ)) && isFin" ascii
    $s3  = "var esdlYFdjwsdtR=[];for(SaYVDhN=(-454+454)/165;SaYVDhN<(20888+744)/169;SaYVDhN++){esdlYFdjwsdtR[SaYVDhN]=String.fromCharCode(Sa" ascii
    $s4  = "push(\"40\");B.push(\"50\");B.push(\"57\");B.push(\"53\");B.push(\"53\");B.push(\"48\");B.push(\"48\");B.push(\"44\");B.push(\"3" ascii
    $s5  = "YVDhN)}function YjyRk(uwHNKlpbWlf,VsXtJIfGbnBAs,AWAQFaCW){ObAl=parseInt(uwHNKlpbWlf,VsXtJIfGbnBAs);eICcM=ObAl.toString(AWAQFaCW)" ascii
    $s6  = "push(\"59\");e.push(\"9\");e.push(\"32\");e.push(\"13\");e.push(\"10\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32" ascii
    $s7  = "push(\"97\");e.push(\"116\");e.push(\"117\");e.push(\"115\");e.push(\"32\");e.push(\"61\");e.push(\"61\");e.push(\"32\");e.push(" ascii
    $s8  = ";return eICcM;}function DAcNEKaLFyxmoDL(OEfchIGBpWMuFAwap){eval(OEfchIGBpWMuFAwap)}" fullword ascii
    $s9  = "function jCTkqIDpeZDkYPisQBQFtgEONBJVyqXIURFFQFpVzaNHJSOTRIhpoW(IuZDsswAUPMJy,ofYyASTBnzorew){ return esdlYFdjwsdtR[YjyRk(IuZDss" ascii
    $s10 = "push(\"32\");B.push(\"48\");B.push(\"59\");B.push(\"13\");B.push(\"10\");B.push(\"118\");B.push(\"97\");B.push(\"114\");B.push(" ascii
    $s11 = "push(\"75\");e.push(\"114\");e.push(\"46\");e.push(\"115\");e.push(\"105\");e.push(\"122\");e.push(\"101\");e.push(\"32\");e.pus" ascii
    $s12 = "push(\"59\");B.push(\"13\");B.push(\"10\");B.push(\"118\");B.push(\"97\");B.push(\"114\");B.push(\"32\");B.push(\"119\");B.push(" ascii
    $s13 = "function jCTkqIDpeZDkYPisQBQFtgEONBJVyqXIURFFQFpVzaNHJSOTRIhpoW(IuZDsswAUPMJy,ofYyASTBnzorew){ return esdlYFdjwsdtR[YjyRk(IuZDss" ascii
    $s14 = "function zlKmkLVaMFFdDFEyn(Xxlrr){pAbmxLQxncE= '';for(ZeVHrUcySyP=(-265+265)/290; ZeVHrUcySyP < (1482+250)/866; ZeVHrUcySyP++) {" ascii
    $s15 = ";}} return pAbmxLQxncE}" fullword ascii
    $s16 = "push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"66\");e.push(\"104\");e.push(\"" ascii
    $s17 = "hPWokgWNp[ZeVHrUcySyP]=(-133+133)/779; while(true) { if(hPWokgWNp[ZeVHrUcySyP] > Xxlrr[ZeVHrUcySyP].length-(-5+117)/112) { break" ascii
    $s18 = "function zlKmkLVaMFFdDFEyn(Xxlrr){pAbmxLQxncE= '';for(ZeVHrUcySyP=(-265+265)/290; ZeVHrUcySyP < (1482+250)/866; ZeVHrUcySyP++) {" ascii
    $s19 = "push(\"59\");B.push(\"13\");B.push(\"10\");B.push(\"118\");B.push(\"97\");B.push(\"114\");B.push(\"32\");B.push(\"77\");B.push(" ascii
    $s20 = "function pGOnISQzEGm(IIdlcvNj,wXgolP){return IIdlcvNj.split(wXgolP)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}