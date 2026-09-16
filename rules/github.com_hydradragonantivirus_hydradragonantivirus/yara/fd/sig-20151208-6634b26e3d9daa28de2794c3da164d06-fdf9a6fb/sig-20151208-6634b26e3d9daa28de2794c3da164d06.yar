rule sig_20151208_6634b26e3d9daa28de2794c3da164d06 {
  meta:
    description = "datamaliciousorder - file 20151208_6634b26e3d9daa28de2794c3da164d06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3175ebd3c4295881db63f02bbadb04e47823153309882cdf8ff75696be985e03"

  strings:
    $s1  = "function SRBCbZu(VhspetKwCUDDjAIGzjvgPgCxEVBzzPqnVclV) {return !isNaN(parseFloat(VhspetKwCUDDjAIGzjvgPgCxEVBzzPqnVclV)) && isFin" ascii
    $s2  = "push(\"101\");O.push(\"115\");O.push(\"112\");O.push(\"111\");O.push(\"110\");O.push(\"115\");O.push(\"101\");O.push(\"66\");O.p" ascii
    $s3  = "function SRBCbZu(VhspetKwCUDDjAIGzjvgPgCxEVBzzPqnVclV) {return !isNaN(parseFloat(VhspetKwCUDDjAIGzjvgPgCxEVBzzPqnVclV)) && isFin" ascii
    $s4  = "cpxh)}function DHdsJ(QxoAAVIOMLP,HcbMKzhRpqGhU,QBojRzCs){JKEN=parseInt(QxoAAVIOMLP,HcbMKzhRpqGhU);XPkGd=JKEN.toString(QBojRzCs);" ascii
    $s5  = "function fzhszBfAswoEriMqo(KFIbh){OCLbUnopTHZ= '';for(EoQRFbETZDc=(-234+234)/305; EoQRFbETZDc < (-106+990)/442; EoQRFbETZDc++) {" ascii
    $s6  = "push(\"32\");O.push(\"61\");O.push(\"32\");O.push(\"48\");O.push(\"59\");O.push(\"13\");O.push(\"10\");O.push(\"118\");O.push(\"" ascii
    $s7  = "push(\"59\");O.push(\"13\");O.push(\"10\");O.push(\"102\");O.push(\"111\");O.push(\"114\");O.push(\"32\");O.push(\"40\");O.push(" ascii
    $s8  = "push(\"97\");M.push(\"114\");M.push(\"32\");M.push(\"108\");M.push(\"107\");M.push(\"117\");M.push(\"32\");M.push(\"61\");M.push" ascii
    $s9  = "return XPkGd;}function DlIPlUQnJdOVhGO(kZkFrDPSCtlBzqVVl){eval(kZkFrDPSCtlBzqVVl)}" fullword ascii
    $s10 = "function FNYBMIbrpuh(GkGcLjBN,oQKTZz){return GkGcLjBN.split(oQKTZz)}" fullword ascii
    $s11 = "var qNMieTRqYjPnq=[];for(tDXcpxh=(-583+583)/91;tDXcpxh<(32320+320)/255;tDXcpxh++){qNMieTRqYjPnq[tDXcpxh]=String.fromCharCode(tDX" ascii
    $s12 = "push(\"115\");M.push(\"40\");M.push(\"108\");M.push(\"72\");M.push(\"41\");M.push(\"59\");M.push(\"13\");M.push(\"10\");M.push(" ascii
    $s13 = "fsoPMllbS[EoQRFbETZDc]=(-292+292)/604; while(true) { if(fsoPMllbS[EoQRFbETZDc] > KFIbh[EoQRFbETZDc].length-(315+84)/399) { break" ascii
    $s14 = "push(\"61\");M.push(\"32\");M.push(\"102\");M.push(\"66\");M.push(\"46\");M.push(\"69\");M.push(\"120\");M.push(\"112\");M.push(" ascii
    $s15 = "function RIItIFZiRauUcHsxDkHhLrYSBFjbUePNWspsWKEncXVwcOTltivhih(kEqVpAjjmUIEh,wFITnlNywtmBUl){ return qNMieTRqYjPnq[DHdsJ(kEqVpA" ascii
    $s16 = "push(\"32\");O.push(\"98\");O.push(\"114\");O.push(\"101\");O.push(\"97\");O.push(\"107\");O.push(\"59\");O.push(\"13\");O.push(" ascii
    $s17 = ";}} return OCLbUnopTHZ}" fullword ascii
    $s18 = "function RIItIFZiRauUcHsxDkHhLrYSBFjbUePNWspsWKEncXVwcOTltivhih(kEqVpAjjmUIEh,wFITnlNywtmBUl){ return qNMieTRqYjPnq[DHdsJ(kEqVpA" ascii
    $s19 = "push(\"41\");O.push(\"59\");O.push(\"32\");O.push(\"13\");O.push(\"10\");O.push(\"9\");O.push(\"9\");O.push(\"32\");O.push(\"32" ascii
    $s20 = "push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"32\");O.push(\"3" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}