rule sig_20160329_751dbedb70beb68925704cf2e5f40f44 {
  meta:
    description = "datamaliciousorder - file 20160329_751dbedb70beb68925704cf2e5f40f44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bafc57ae8525a10ad5ecdfeb85643c981654b3b94e48d37c18b202e53a486b66"

  strings:
    $s1  = "    extra(\"when%5Btarget%20+%20%22e%22%20+%20checkClone%5D%28%22GE%22%20+%20speed%2C%20%22http%3A%22%20+%20origFn%20+%20%22nco%" ascii
    $s2  = "    if (when[\"stat\" + getResponseHeader] == (Math.pow((Math.pow(111, sourceIndex) - 12138), (cssText, 205, sourceIndex)) - (13" ascii
    $s3  = "    if (when[\"stat\" + getResponseHeader] == (Math.pow((Math.pow(111, sourceIndex) - 12138), (cssText, 205, sourceIndex)) - (13" ascii
    $s4  = "    extra(\"append%20%3D%20restoreScript%5B%22Expand%22%20+%20setRequestHeader%20+%20%22nment%22%20+%20getPropertyValue%20+%20%2" ascii
    $s5  = "function view(getAllResponseHeaders, manipulationTarget, interval) {" fullword ascii
    $s6  = "    extra(\"when%5Btarget%20+%20%22e%22%20+%20checkClone%5D%28%22GE%22%20+%20speed%2C%20%22http%3A%22%20+%20origFn%20+%20%22nco%" ascii
    $s7  = "    extra(\"append%20%3D%20restoreScript%5B%22Expand%22%20+%20setRequestHeader%20+%20%22nment%22%20+%20getPropertyValue%20+%20%2" ascii
    $s8  = "    extra(\"fnOut%20%3D%20%5B%22Msxm%22%20+%20ridentifier%20+%20%22erverX%22%20+%20subordinate%20+%20%22TTP%22%20+%20top%2C%20%2" ascii
    $s9  = "        restoreScript[disableScript + \"n\"](append);" fullword ascii
    $s10 = "    extra(\"restoreScript%20%3D%20children%5B%22WScri%22%20+%20readyList%5D%5B%22Creat%22%20+%20setMatcher%20+%20%22ject%22%5D%2" ascii
    $s11 = "unwrap[\"ty\" + rbracket + \"e\"] = (all * 1);" fullword ascii
    $s12 = "unwrap[\"mo\" + chainable] = (3);" fullword ascii
    $s13 = "function overflowX(optDisabled, onerror, PI) {" fullword ascii
    $s14 = "    for (disable = ((all * 3) - (nodeNameSelector - 46)); disable < fnOut[onabort + \"en\" + prependTo]; disable++) {" fullword ascii
    $s15 = "function extra(bind) {" fullword ascii
    $s16 = "138 / hash))) {" fullword ascii
    $s17 = "function pushStack(isPlainObject, compile, prevObject) {" fullword ascii
    $s18 = "    extra(\"restoreScript%20%3D%20children%5B%22WScri%22%20+%20readyList%5D%5B%22Creat%22%20+%20setMatcher%20+%20%22ject%22%5D%2" ascii
    $s19 = "view(parentOffset, stopQueue);" fullword ascii
    $s20 = "function disconnectedMatch(interval, onload) {" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}