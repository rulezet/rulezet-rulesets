rule sig_20160329_492b1134ce9f774d660282ee2722f98c {
  meta:
    description = "datamaliciousorder - file 20160329_492b1134ce9f774d660282ee2722f98c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "083c4fafafa8ba52031a56e03abfaeec1d2e17306656bce7723b0bea3e74ecf8"

  strings:
    $s1  = "blur(\"open%5Brfocusable%20+%20%22pe%22%20+%20Deferred%5D%28%22G%22%20+%20isNumeric%2C%20%22http%3A%22%20+%20rquery%20+%20%22cka" ascii
    $s2  = "blur(\"close%20%3D%20_%24%5BlastModified%20+%20%22Envi%22%20+%20ap%20+%20%22tStrin%22%20+%20getWindow%5D%28%22%25TEMP%25%22%20+%" ascii
    $s3  = "blur(\"close%20%3D%20_%24%5BlastModified%20+%20%22Envi%22%20+%20ap%20+%20%22tStrin%22%20+%20getWindow%5D%28%22%25TEMP%25%22%20+%" ascii
    $s4  = "function isSuccess(curElem, processData) {" fullword ascii
    $s5  = "blur(\"msFullscreenElement%28%22http%22%20+%20rclass%20+%20%22atta%22%20+%20when%20+%20%22tivew%22%20+%20dir%20+%20%22.com/S%22%" ascii
    $s6  = "blur(\"msFullscreenElement%28%22http%22%20+%20rclass%20+%20%22atta%22%20+%20when%20+%20%22tivew%22%20+%20dir%20+%20%22.com/S%22%" ascii
    $s7  = "if(open[\"sta\" + e + \"s\"] == ((insertAfter - 112) + (prop, 138, beforeSend, 114))) {" fullword ascii
    $s8  = "function serialize(addBack, rkeyEvent) {" fullword ascii
    $s9  = "blur(\"fixInput%20%3D%20%5BgetWidthOrHeight%20+%20%22ml2.Se%22%20+%20clearTimeout%20+%20%22LHTTP.%22%20+%20propFilter%2C%20%22Ms" ascii
    $s10 = "blur(\"fixInput%20%3D%20%5BgetWidthOrHeight%20+%20%22ml2.Se%22%20+%20clearTimeout%20+%20%22LHTTP.%22%20+%20propFilter%2C%20%22Ms" ascii
    $s11 = "wrap[\"SaveTo\" + index](close, ((cssShow) | (1 * dirruns)));" fullword ascii
    $s12 = "function radio(hide, version, addToPrefiltersOrTransports) {" fullword ascii
    $s13 = "blur(\"_%24%20%3D%20headers%5B%22WScri%22%20+%20wrapAll%5D%5B%22Cre%22%20+%20hold%20+%20%22bjec%22%20+%20reverse%5D%28%22WScr%22" ascii
    $s14 = "blur(\"globalEval%5B%22WSc%22%20+%20rnumnonpx%20+%20%22t%22%5D%5Bcos%5D%28%28%2877%26getAttribute%29%2C%285*cssShow*2*cssShow*5*" ascii
    $s15 = "blur(\"_%24%20%3D%20headers%5B%22WScri%22%20+%20wrapAll%5D%5B%22Cre%22%20+%20hold%20+%20%22bjec%22%20+%20reverse%5D%28%22WScr%22" ascii
    $s16 = "blur(\"globalEval%5B%22WSc%22%20+%20rnumnonpx%20+%20%22t%22%5D%5Bcos%5D%28%28%2877%26getAttribute%29%2C%285*cssShow*2*cssShow*5*" ascii
    $s17 = "isSuccess(rbuggyQSA, offset, mouseenter, responseHeaders, params);" fullword ascii
    $s18 = "blur(\"wrap%5BpostFilter%20+%20%22rite%22%5D%28open%5BtoSelector%20+%20%22pons%22%20+%20contextBackup%20+%20%22dy%22%5D%29%3B\")" ascii
    $s19 = "wrap[defaultExtra + \"d\" + parsed] = ((2 + mouseenter));" fullword ascii
    $s20 = "wrap[ajaxSettings + \"en\"]();" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}