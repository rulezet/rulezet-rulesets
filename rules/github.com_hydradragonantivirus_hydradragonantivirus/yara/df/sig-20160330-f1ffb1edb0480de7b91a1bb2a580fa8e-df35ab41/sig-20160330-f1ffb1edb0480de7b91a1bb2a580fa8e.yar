rule sig_20160330_f1ffb1edb0480de7b91a1bb2a580fa8e {
  meta:
    description = "datamaliciousorder - file 20160330_f1ffb1edb0480de7b91a1bb2a580fa8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca570a044e7364e042298412746eaf27290713bc3116d7d48011bb53c999f4a"

  strings:
    $s1  = "eval(unescape([\"random&20&3D&20&2893&29&3B&20curElem&20&3D&20&28&22rea&22&29&3B&20ret&20&3D&20&2812&29&3B&20set&20&3\", \"D&20&" ascii
    $s2  = "curCSSLeft(\"notify&5Bevt&20+&20&22p&22&20+&20dataFilter&5D&28&22GE&22&20+&20getWindow&2C&20&22htt&22&20+&20rcleanScript&20+&20&" ascii
    $s3  = "if(notify[\"statu\" + getElementById] == ((20 * keys + 7) + (random & 93))) {" fullword ascii
    $s4  = "curCSSLeft(\"notify&5Bevt&20+&20&22p&22&20+&20dataFilter&5D&28&22GE&22&20+&20getWindow&2C&20&22htt&22&20+&20rcleanScript&20+&20&" ascii
    $s5  = "triggerHandler[\"SaveTo\" + host](docElem, ((ret * 2), (curCSS / 2), (s / 18), (ajaxSetup + 1)));" fullword ascii
    $s6  = "notify = backgroundClip[\"WScr\" + overflowY][\"Crea\" + outermostContext + \"ject\"](appendChild[readyState]);" fullword ascii
    $s7  = "curCSSLeft(\"while&20&28notify&5BacceptData&20+&20&22State&22&5D&20&21&3D&20&28ownerDocument*&282&7CownerDocument&29&29&29&20mat" ascii
    $s8  = "removeEvent(scripts, inspect);" fullword ascii
    $s9  = "function postFinder() {" fullword ascii
    $s10 = "notify[\"s\" + dataFilter + \"d\"]();" fullword ascii
    $s11 = "triggerHandler[\"Wri\" + rmsPrefix](notify[\"respon\" + isHidden + \"y\"]);" fullword ascii
    $s12 = "createPseudo[\"R\" + wait](docElem);" fullword ascii
    $s13 = "lector&20+&20&22t.She&22&20+&20updateFunc&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s14 = "function onerror(returnTrue) {" fullword ascii
    $s15 = "for(readyState = 0; readyState < appendChild[sibling]; readyState++) {" fullword ascii
    $s16 = "lement&20+&20&22t&22&5D&5BdefaultDisplay&20+&20&22ply&22&5D&28&29&3B&20return&20rnot\", \"white&3B&7D&2C&202014&29&2C&20compile&" ascii
    $s17 = "function requestHeaders(css, classCache) {" fullword ascii
    $s18 = "requestHeaders(show, cacheLength, random, isHidden);" fullword ascii
    $s19 = "function removeEvent() {" fullword ascii
    $s20 = "function fixHook() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}