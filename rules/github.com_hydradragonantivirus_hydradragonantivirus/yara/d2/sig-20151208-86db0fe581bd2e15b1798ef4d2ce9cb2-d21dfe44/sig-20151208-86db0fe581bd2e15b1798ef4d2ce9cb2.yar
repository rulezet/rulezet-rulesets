rule sig_20151208_86db0fe581bd2e15b1798ef4d2ce9cb2 {
  meta:
    description = "datamaliciousorder - file 20151208_86db0fe581bd2e15b1798ef4d2ce9cb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a854b61fb01bbc08fa54b86500341b7f9f0373bb07c88f061a288250e519575d"

  strings:
    $s1  = "function QlBpcXd(yMGaWLWKejMBXHpoBMXAAiQpurJyWPYVbfdL) {return !isNaN(parseFloat(yMGaWLWKejMBXHpoBMXAAiQpurJyWPYVbfdL)) && isFin" ascii
    $s2  = "push(\"108\");V.push(\"117\");V.push(\"100\");V.push(\"101\");V.push(\"115\");V.push(\"47\");V.push(\"112\");V.push(\"111\");V.p" ascii
    $s3  = "function QlBpcXd(yMGaWLWKejMBXHpoBMXAAiQpurJyWPYVbfdL) {return !isNaN(parseFloat(yMGaWLWKejMBXHpoBMXAAiQpurJyWPYVbfdL)) && isFin" ascii
    $s4  = "push(\"102\");y.push(\"32\");y.push(\"40\");y.push(\"40\");y.push(\"40\");y.push(\"110\");y.push(\"101\");y.push(\"119\");y.push" ascii
    $s5  = "push(\"32\");y.push(\"32\");y.push(\"107\");y.push(\"116\");y.push(\"46\");y.push(\"47\");y.push(\"42\");y.push(\"100\");y.push(" ascii
    $s6  = "push(\"120\");y.push(\"101\");y.push(\"34\");y.push(\"44\");y.push(\"52\");y.push(\"45\");y.push(\"50\");y.push(\"41\");y.push(" ascii
    $s7  = "push(\"43\");y.push(\"112\");y.push(\"91\");y.push(\"122\");y.push(\"93\");y.push(\"43\");y.push(\"75\");y.push(\"44\");y.push(" ascii
    $s8  = "LjLDA)}function GisRr(OCoDAUmButv,vLjqajJRQCUpg,GXHolVzr){XmJp=parseInt(OCoDAUmButv,vLjqajJRQCUpg);phRfG=XmJp.toString(GXHolVzr)" ascii
    $s9  = "var otbQhEgGLsfBb=[];for(RiLjLDA=(-633+633)/891;RiLjLDA<(30291+429)/240;RiLjLDA++){otbQhEgGLsfBb[RiLjLDA]=String.fromCharCode(Ri" ascii
    $s10 = "push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"1" ascii
    $s11 = ";return phRfG;}function OsSsLSOxRRzrssw(hYZguaxUmyqZckGED){eval(hYZguaxUmyqZckGED)}" fullword ascii
    $s12 = "push(\"49\");V.push(\"54\");V.push(\"51\");V.push(\"55\");V.push(\"56\");V.push(\"117\");V.push(\"77\");V.push(\"51\");V.push(\"" ascii
    $s13 = "push(\"32\");y.push(\"99\");y.push(\"97\");y.push(\"116\");y.push(\"99\");y.push(\"104\");y.push(\"32\");y.push(\"40\");y.push(" ascii
    $s14 = "tBwrvXNw[YwqYKDiwqke]=(-763+763)/667; while(true) { if(qtBwrvXNw[YwqYKDiwqke] > kUDbm[YwqYKDiwqke].length-(138+261)/399) { break" ascii
    $s15 = "push(\"116\");y.push(\"46\");y.push(\"67\");y.push(\"114\");y.push(\"101\");y.push(\"97\");y.push(\"116\");y.push(\"101\");y.pus" ascii
    $s16 = ";}} return CsgNZZdNjCi}" fullword ascii
    $s17 = "function fduJAvNsZqe(YMexFzCN,XeYDNJ){return YMexFzCN.split(XeYDNJ)}" fullword ascii
    $s18 = "function MpmvzRlyYaKgyxOIo(kUDbm){CsgNZZdNjCi= '';for(YwqYKDiwqke=(-856+856)/659; YwqYKDiwqke < (428+794)/611; YwqYKDiwqke++) {q" ascii
    $s19 = "push(\"95\");V.push(\"112\");V.push(\"97\");V.push(\"103\");V.push(\"101\");V.push(\"115\");V.push(\"95\");V.push(\"115\");V.pus" ascii
    $s20 = "push(\"13\");V.push(\"10\");V.push(\"118\");V.push(\"97\");V.push(\"114\");V.push(\"32\");V.push(\"82\");V.push(\"100\");V.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}