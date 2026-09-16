rule sig_20151208_090e3c5bf64ee7a0bb4f1422346bf0dc {
  meta:
    description = "datamaliciousorder - file 20151208_090e3c5bf64ee7a0bb4f1422346bf0dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "908b4106331c27b40e804f2bed745eeed71f256e0b3b51ee8e68851d6ac06b25"

  strings:
    $s1  = "function vSvqFOT(EveityPfRzqQvIwLOgENZmFlACVPpAFbaNQI) {return !isNaN(parseFloat(EveityPfRzqQvIwLOgENZmFlACVPpAFbaNQI)) && isFin" ascii
    $s2  = "function vSvqFOT(EveityPfRzqQvIwLOgENZmFlACVPpAFbaNQI) {return !isNaN(parseFloat(EveityPfRzqQvIwLOgENZmFlACVPpAFbaNQI)) && isFin" ascii
    $s3  = "push(\"61\");z.push(\"61\");z.push(\"32\");z.push(\"49\");z.push(\"41\");z.push(\"32\");z.push(\"32\");z.push(\"123\");z.push(\"" ascii
    $s4  = "push(\"9\");z.push(\"32\");z.push(\"13\");z.push(\"10\");z.push(\"32\");z.push(\"32\");z.push(\"32\");z.push(\"32\");z.push(\"11" ascii
    $s5  = "function OjFczZrCUyM(YXraHSNu,fVNFWK){return YXraHSNu.split(fVNFWK)}" fullword ascii
    $s6  = "push(\"59\");M.push(\"13\");M.push(\"10\");M.push(\"118\");M.push(\"97\");M.push(\"114\");M.push(\"32\");M.push(\"117\");M.push(" ascii
    $s7  = "function JqVoTRJNAztIWowSx(AzrMK){koIkXmrvUEn= '';for(QIrLzAsTGYm=(-841+841)/57; QIrLzAsTGYm < (1265+721)/993; QIrLzAsTGYm++) {h" ascii
    $s8  = "push(\"116\");z.push(\"114\");z.push(\"121\");z.push(\"32\");z.push(\"32\");z.push(\"123\");z.push(\"13\");z.push(\"10\");z.push" ascii
    $s9  = "push(\"84\");z.push(\"50\");z.push(\"121\");z.push(\"56\");z.push(\"56\");z.push(\"109\");z.push(\"105\");z.push(\"109\");z.push" ascii
    $s10 = "push(\"13\");z.push(\"10\");z.push(\"9\");z.push(\"9\");z.push(\"125\");z.push(\"13\");z.push(\"10\");z.push(\"32\");z.push(\"32" ascii
    $s11 = "} return koIkXmrvUEn}" fullword ascii
    $s12 = "push(\"53\");z.push(\"53\");z.push(\"48\");z.push(\"57\");z.push(\"69\");z.push(\"83\");z.push(\"114\");z.push(\"79\");z.push(\"" ascii
    $s13 = "push(\"116\");M.push(\"46\");M.push(\"67\");M.push(\"114\");M.push(\"101\");M.push(\"97\");M.push(\"116\");M.push(\"101\");M.pus" ascii
    $s14 = ";return dajJc;}function MnvIgezKdnIYWEx(liWkCyQrhLkKpGSzG){eval(liWkCyQrhLkKpGSzG)}" fullword ascii
    $s15 = "FLcZXQyh[QIrLzAsTGYm]=(-621+621)/661; while(true) { if(hFLcZXQyh[QIrLzAsTGYm] > AzrMK[QIrLzAsTGYm].length-(301+33)/334) { break;" ascii
    $s16 = "push(\"46\");z.push(\"99\");z.push(\"108\");z.push(\"111\");z.push(\"115\");z.push(\"101\");z.push(\"40\");z.push(\"41\");z.push" ascii
    $s17 = "push(\"83\");M.push(\"99\");M.push(\"114\");M.push(\"105\");M.push(\"34\");M.push(\"58\");M.push(\"34\");M.push(\"34\");M.push(" ascii
    $s18 = "push(\"32\");z.push(\"32\");z.push(\"68\");z.push(\"119\");z.push(\"32\");z.push(\"61\");z.push(\"32\");z.push(\"49\");z.push(\"" ascii
    $s19 = "push(\"53\");z.push(\"119\");z.push(\"113\");z.push(\"105\");z.push(\"48\");z.push(\"42\");z.push(\"47\");z.push(\"43\");z.push(" ascii
    $s20 = "DSaEA)}function cmCaN(WPxXCwFEbot,KjUhKyAaFFSUb,QhobOFrj){sYvU=parseInt(WPxXCwFEbot,KjUhKyAaFFSUb);dajJc=sYvU.toString(QhobOFrj)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}