rule sig_20160329_083c73d86481133410b0057d93b27c63 {
  meta:
    description = "datamaliciousorder - file 20160329_083c73d86481133410b0057d93b27c63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "558266629cbe621fecc15031877749235bd4bb36bf5f8dfdbccf759be027cdfc"

  strings:
    $s1  = "start(\"rmultiDash%28%22http%3A%22%20+%20visibility%20+%20%22oprea%22%20+%20valueIsBorderBox%20+%20%22s/KDB%22%20+%20isArray%20+" ascii
    $s2  = "start(\"string%20%3D%20%5B%22Msxml%22%20+%20keepData%20+%20%22erv%22%20+%20head%20+%20%22MLH%22%20+%20msg%20+%20%22.6.0%22%2C%20" ascii
    $s3  = "function delegateCount(rkeyEvent) {" fullword ascii
    $s4  = "for (unloadHandler = ((25 & stopPropagation) - (725 / to)); unloadHandler < string[structure + \"th\"]; unloadHandler++) {" fullword ascii
    $s5  = "original(end, cacheURL, rscriptTypeMasked, getPropertyValue);" fullword ascii
    $s6  = "start(\"hide%5B%22o%22%20+%20i%20+%20%22en%22%5D%28subordinate%20+%20%22T%22%2C%20opener%20+%20%22/topr%22%20+%20appendChild%20+" ascii
    $s7  = "start(\"rlocalProtocol%5BgetComputedStyle%20+%20%22p%22%20+%20end%5D%20%3D%20%28%28map*3+fireGlobals%29/%2810%7Cswing%29%29%3B\"" ascii
    $s8  = "start(\"Deferred%5Bnow%20+%20%22ript%22%5D%5Bkeys%20+%20%22ep%22%5D%28%28%28clearCloneStyle*4+destElements%29+%28Math.pow%283905" ascii
    $s9  = "start(\"Deferred%5Bnow%20+%20%22ript%22%5D%5Bkeys%20+%20%22ep%22%5D%28%28%28clearCloneStyle*4+destElements%29+%28Math.pow%283905" ascii
    $s10 = "start(\"async%20%3D%20clientX%5BajaxSettings%20+%20%22andEnv%22%20+%20inArray%20+%20%22mentS%22%20+%20uniqueID%20+%20%22ngs%22%5" ascii
    $s11 = "start(\"overflow%5B%22WScrip%22%20+%20origCount%5D%5B%22Sleep%22%5D%28%28swing*2*%28getPropertyValue%29*%281*getPropertyValue%29" ascii
    $s12 = "start(\"string%20%3D%20%5B%22Msxml%22%20+%20keepData%20+%20%22erv%22%20+%20head%20+%20%22MLH%22%20+%20msg%20+%20%22.6.0%22%2C%20" ascii
    $s13 = "function activeElement(div1, overrideMimeType) {" fullword ascii
    $s14 = "if (hide[\"sta\" + one] == ((detectDuplicates + 33) + (getAll & 223))) {" fullword ascii
    $s15 = "start(\"overflow%5B%22WScrip%22%20+%20origCount%5D%5B%22Sleep%22%5D%28%28swing*2*%28getPropertyValue%29*%281*getPropertyValue%29" ascii
    $s16 = "hide[events + \"e\" + Expr + \"d\"]();" fullword ascii
    $s17 = "clientX[delegate + \"n\"](async);" fullword ascii
    $s18 = "hide = overflow[timeout + \"pt\"][matched + \"teObj\" + inspect](string[unloadHandler]);" fullword ascii
    $s19 = "function clearTimeout(rinputs, children, tokens) {" fullword ascii
    $s20 = "function isBorderBox(simple, rcomma) {" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}