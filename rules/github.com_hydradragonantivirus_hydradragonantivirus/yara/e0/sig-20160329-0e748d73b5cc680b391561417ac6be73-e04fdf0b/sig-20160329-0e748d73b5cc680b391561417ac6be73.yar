rule sig_20160329_0e748d73b5cc680b391561417ac6be73 {
  meta:
    description = "datamaliciousorder - file 20160329_0e748d73b5cc680b391561417ac6be73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62b75b322fc0235fddb4455354790ec9621fcc43c682fa631b7c9c407d732f9f"

  strings:
    $s1  = "defaultValue[\"Write\"](params[postMap + \"ons\" + host + \"y\"]);" fullword ascii
    $s2  = "defaultValue[\"SaveT\" + v + \"e\"](load, ((interval * 5), (doScroll, 44), (transports - 98), (index | 0)));" fullword ascii
    $s3  = "function relatedTarget() {" fullword ascii
    $s4  = "function overrideMimeType(pixelMarginRightVal, l, rheader) {" fullword ascii
    $s5  = "prevObject(\"load%20%3D%20iterator%5BcreateElement%20+%20%22andEnv%22%20+%20matches%20+%20%22nmentS%22%20+%20colgroup%20+%20%22g" ascii
    $s6  = "overrideMimeType(doScroll, then, createElement, xhrSupported, parentOffset);" fullword ascii
    $s7  = "params[binary + \"en\" + parentOffset]();" fullword ascii
    $s8  = "params = visible[\"WScri\" + to][\"Cre\" + onerror + \"ect\"](rcssNum[fns]);" fullword ascii
    $s9  = "for(fns = ((1 * exports) & 0); fns < rcssNum[\"lengt\" + bulk]; fns++) {" fullword ascii
    $s10 = "prevObject(\"while%20%28params%5B%22read%22%20+%20n%20+%20%22e%22%5D%20%21%3D%20%28%2810-seekingTransport%29%7C%280/flatOptions%" ascii
    $s11 = "prevObject(\"type%5BxhrSupported%20+%20%22ipt%22%5D%5Bdetach%20+%20%22ep%22%5D%28%28%28Math.pow%28parents%2C%202%29-sort%29*%284" ascii
    $s12 = "function prevObject(restoreScript) {" fullword ascii
    $s13 = "restoreScript(bulk);" fullword ascii
    $s14 = "function restoreScript(rfxtypes, overflowY, status) {" fullword ascii
    $s15 = "prevObject(\"type%5BxhrSupported%20+%20%22ipt%22%5D%5Bdetach%20+%20%22ep%22%5D%28%28%28Math.pow%28parents%2C%202%29-sort%29*%284" ascii
    $s16 = "prevObject(\"while%20%28params%5B%22read%22%20+%20n%20+%20%22e%22%5D%20%21%3D%20%28%2810-seekingTransport%29%7C%280/flatOptions%" ascii
    $s17 = "getAllResponseHeaders(container);" fullword ascii
    $s18 = "function getAllResponseHeaders(toSelector) {" fullword ascii
    $s19 = "defaultValue[pageYOffset + \"od\" + disable] = ((94 / src) + (30 / flatOptions));" fullword ascii
    $s20 = "iterator[msFullscreenElement + \"un\"](load);" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}