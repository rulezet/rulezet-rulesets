rule sig_20151208_f130dd7b3650e55b9018f07376fbe564 {
  meta:
    description = "datamaliciousorder - file 20151208_f130dd7b3650e55b9018f07376fbe564.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0b06600904ced45d25616b90008bdfb6376a4e3490c70404b7b3ff771da6f82"

  strings:
    $s1  = "push(\"108\");Z.push(\"117\");Z.push(\"100\");Z.push(\"101\");Z.push(\"115\");Z.push(\"47\");Z.push(\"112\");Z.push(\"111\");Z.p" ascii
    $s2  = "function hVjptyq(xTvOhgTbxFSoWBDdtqMRTHERJkiObHWMlgay) {return !isNaN(parseFloat(xTvOhgTbxFSoWBDdtqMRTHERJkiObHWMlgay)) && isFin" ascii
    $s3  = "function hVjptyq(xTvOhgTbxFSoWBDdtqMRTHERJkiObHWMlgay) {return !isNaN(parseFloat(xTvOhgTbxFSoWBDdtqMRTHERJkiObHWMlgay)) && isFin" ascii
    $s4  = "var WrvwrWKGrQKjc=[];for(OMlSLhw=(-657+657)/927;OMlSLhw<(91013+635)/716;OMlSLhw++){WrvwrWKGrQKjc[OMlSLhw]=String.fromCharCode(OM" ascii
    $s5  = "tXCvoQv[NisMjtwIHwq]=(-943+943)/929; while(true) { if(cotXCvoQv[NisMjtwIHwq] > VxGOt[NisMjtwIHwq].length-(-430+920)/490) { break" ascii
    $s6  = "push(\"40\");F.push(\"54\");F.push(\"54\");F.push(\"49\");F.push(\"51\");F.push(\"48\");F.push(\"54\");F.push(\"44\");F.push(\"3" ascii
    $s7  = "push(\"51\");Z.push(\"52\");Z.push(\"49\");Z.push(\"49\");" fullword ascii
    $s8  = "push(\"117\");Z.push(\"77\");Z.push(\"81\");Z.push(\"32\");Z.push(\"61\");Z.push(\"32\");Z.push(\"34\");Z.push(\"50\");Z.push(\"" ascii
    $s9  = "lSLhw)}function GbNPn(WRIzzAokQoS,jGfdOrDvfIuDv,oqwSYXDQ){nRRU=parseInt(WRIzzAokQoS,jGfdOrDvfIuDv);QJIYw=nRRU.toString(oqwSYXDQ)" ascii
    $s10 = "push(\"102\");F.push(\"79\");F.push(\"90\");F.push(\"68\");F.push(\"43\");F.push(\"47\");F.push(\"42\");F.push(\"107\");F.push(" ascii
    $s11 = "push(\"49\");F.push(\"41\");F.push(\"32\");F.push(\"32\");F.push(\"123\");F.push(\"13\");F.push(\"10\");F.push(\"32\");F.push(\"" ascii
    $s12 = ";return QJIYw;}function GpXsYdiPyCjcxwO(bVhBFXIFVpFoQWoqI){eval(bVhBFXIFVpFoQWoqI)}" fullword ascii
    $s13 = "push(\"34\");Z.push(\"34\");Z.push(\"41\");Z.push(\"43\");Z.push(\"34\");Z.push(\"112\");Z.push(\"116\");Z.push(\"46\");Z.push(" ascii
    $s14 = "push(\"32\");F.push(\"13\");F.push(\"10\");F.push(\"32\");F.push(\"32\");F.push(\"32\");F.push(\"32\");F.push(\"105\");F.push(\"" ascii
    $s15 = "push(\"32\");F.push(\"32\");F.push(\"32\");F.push(\"32\");F.push(\"32\");F.push(\"32\");F.push(\"69\");F.push(\"117\");F.push(\"" ascii
    $s16 = "function CIGfJOksLZQdHpVzP(VxGOt){oChhzOElPsM= '';for(NisMjtwIHwq=(-15+15)/871; NisMjtwIHwq < (1866+108)/987; NisMjtwIHwq++) {co" ascii
    $s17 = "push(\"51\");F.push(\"54\");F.push(\"56\");F.push(\"45\");F.push(\"54\");F.push(\"52\");F.push(\"52\");F.push(\"41\");F.push(\"3" ascii
    $s18 = "push(\"59\");F.push(\"13\");F.push(\"10\");F.push(\"118\");F.push(\"97\");F.push(\"114\");F.push(\"32\");F.push(\"69\");F.push(" ascii
    $s19 = ";}} return oChhzOElPsM}" fullword ascii
    $s20 = "push(\"32\");F.push(\"40\");F.push(\"40\");F.push(\"40\");F.push(\"110\");F.push(\"101\");F.push(\"119\");F.push(\"32\");F.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}