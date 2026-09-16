rule sig_20151208_5b5c4baa49346927dfd893947668cccd {
  meta:
    description = "datamaliciousorder - file 20151208_5b5c4baa49346927dfd893947668cccd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9d248d729ec90ad1e185ff83b4d7e9cbd56cbb78901393788ce8fc796b73de"

  strings:
    $s1  = "function iNXYRNc(KyTrhHJzmyZfZgDXGriAzZUFIGuEzSIneTCK) {return !isNaN(parseFloat(KyTrhHJzmyZfZgDXGriAzZUFIGuEzSIneTCK)) && isFin" ascii
    $s2  = "function iNXYRNc(KyTrhHJzmyZfZgDXGriAzZUFIGuEzSIneTCK) {return !isNaN(parseFloat(KyTrhHJzmyZfZgDXGriAzZUFIGuEzSIneTCK)) && isFin" ascii
    $s3  = "push(\"32\");q.push(\"52\");q.push(\"56\");q.push(\"48\");q.push(\"53\");q.push(\"54\");q.push(\"48\");q.push(\"59\");q.push(\"1" ascii
    $s4  = "function rSNMDTKmViR(sUvMxdFN,rSxrEe){return sUvMxdFN.split(rSxrEe)}" fullword ascii
    $s5  = "push(\"32\");l.push(\"104\");l.push(\"103\");l.push(\"32\");l.push(\"61\");l.push(\"32\");l.push(\"87\");l.push(\"83\");l.push(" ascii
    $s6  = "push(\"32\");l.push(\"43\");l.push(\"32\");l.push(\"34\");l.push(\"84\");l.push(\"84\");l.push(\"80\");l.push(\"34\");l.push(\"5" ascii
    $s7  = "push(\"13\");q.push(\"10\");q.push(\"118\");q.push(\"97\");q.push(\"114\");q.push(\"32\");q.push(\"90\");q.push(\"110\");q.push(" ascii
    $s8  = "FhYDK)}function Mbrfi(SCLCsFolvtD,RVHdWNidWRllZ,orSTYCgk){vhlI=parseInt(SCLCsFolvtD,RVHdWNidWRllZ);tVCYa=vhlI.toString(orSTYCgk)" ascii
    $s9  = "push(\"101\");l.push(\"79\");l.push(\"98\");l.push(\"106\");l.push(\"101\");l.push(\"99\");l.push(\"116\");l.push(\"40\");l.push" ascii
    $s10 = "+;}} return xqYdwPncRcv}" fullword ascii
    $s11 = "function oHzyWUxgCdPwZXKANHrDtnzFkOhutMmOqXBONJcdcDUldjptNxvdqp(OGxovGBxBNvAS,URzwFMFeZrKwxr){ return LVLawEcyJPHzR[Mbrfi(OGxovG" ascii
    $s12 = "push(\"45\");l.push(\"105\");l.push(\"110\");l.push(\"99\");l.push(\"108\");l.push(\"117\");l.push(\"100\");l.push(\"101\");l.pu" ascii
    $s13 = "function oHzyWUxgCdPwZXKANHrDtnzFkOhutMmOqXBONJcdcDUldjptNxvdqp(OGxovGBxBNvAS,URzwFMFeZrKwxr){ return LVLawEcyJPHzR[Mbrfi(OGxovG" ascii
    $s14 = "function RnqPSGjUhAMxgclWf(aUrxN){xqYdwPncRcv= '';for(GAOAIEUcQuF=(-507+507)/126; GAOAIEUcQuF < (1079+389)/734; GAOAIEUcQuF++) {" ascii
    $s15 = "push(\"51\");l.push(\"48\");l.push(\"54\");l.push(\"57\");l.push(\"53\");l.push(\"57\");l.push(\"54\");l.push(\"110\");l.push(\"" ascii
    $s16 = "push(\"32\");q.push(\"40\");q.push(\"105\");q.push(\"113\");q.push(\"46\");q.push(\"115\");q.push(\"116\");q.push(\"97\");q.push" ascii
    $s17 = "push(\"104\");l.push(\"102\");l.push(\"89\");l.push(\"32\");l.push(\"61\");l.push(\"32\");l.push(\"34\");l.push(\"65\");l.push(" ascii
    $s18 = "FVhzRcsSa[GAOAIEUcQuF]=(-356+356)/667; while(true) { if(FVhzRcsSa[GAOAIEUcQuF] > aUrxN[GAOAIEUcQuF].length-(73+434)/507) { break" ascii
    $s19 = "function RnqPSGjUhAMxgclWf(aUrxN){xqYdwPncRcv= '';for(GAOAIEUcQuF=(-507+507)/126; GAOAIEUcQuF < (1079+389)/734; GAOAIEUcQuF++) {" ascii
    $s20 = "push(\"46\");q.push(\"108\");q.push(\"101\");q.push(\"110\");q.push(\"103\");q.push(\"116\");q.push(\"104\");q.push(\"59\");q.pu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}