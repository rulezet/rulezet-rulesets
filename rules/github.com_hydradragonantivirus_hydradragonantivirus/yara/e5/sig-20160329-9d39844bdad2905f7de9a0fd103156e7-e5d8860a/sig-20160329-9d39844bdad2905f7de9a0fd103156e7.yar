rule sig_20160329_9d39844bdad2905f7de9a0fd103156e7 {
  meta:
    description = "datamaliciousorder - file 20160329_9d39844bdad2905f7de9a0fd103156e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67dd54cfa3b40323c21f8b1434fca421ac443aebffb757e90da54b42d4af2782"

  strings:
    $s1  = "before[tokens + \"t\"][srcElements](((Math.pow(3, Expr) - 5) + (elements / 3)));" fullword ascii
    $s2  = "for (valueIsBorderBox = (1 + -rheader); valueIsBorderBox < ajaxExtend[original + \"ng\" + curTop]; valueIsBorderBox++) {" fullword ascii
    $s3  = "disabled(\"while%20%28getClass%5BgetAll%20+%20%22dySt%22%20+%20etag%5D%20%21%3D%20%28%28now-34%29+%28finish-9%29%29%29%20textCon" ascii
    $s4  = "before = scrollTop = textContent = getter = map.detach();" fullword ascii
    $s5  = "disabled(\"getClass%5BradioValue%20+%20%22en%22%5D%28events%20+%20%22ET%22%2C%20preFilter%20+%20%22//shop%22%20+%20createCache%2" ascii
    $s6  = "disabled(\"isReady%20%3D%20setTimeout%5BpostDispatch%20+%20%22andE%22%20+%20merge%20+%20%22nme%22%20+%20clearTimeout%20+%20%22tr" ascii
    $s7  = "disabled(\"matcherOut%5Bfile%20+%20%22p%22%20+%20dirrunsUnique%5D%20%3D%20%28%281%7Crheader%29+%281+-rheader%29%29%3B\");" fullword ascii
    $s8  = "disabled(\"isReady%20%3D%20setTimeout%5BpostDispatch%20+%20%22andE%22%20+%20merge%20+%20%22nme%22%20+%20clearTimeout%20+%20%22tr" ascii
    $s9  = "matcherOut[slow](getClass[\"respo\" + root + \"dy\"]);" fullword ascii
    $s10 = "if (getClass[rsibling + \"atus\"] == ((compile), (129 + types))) {" fullword ascii
    $s11 = "disabled(\"ajaxExtend%20%3D%20%5B%22Msx%22%20+%20temp%20+%20%22rverXM%22%20+%20createButtonPseudo%20+%20%22P.6.0%22%2C%20allType" ascii
    $s12 = "disabled(\"ajaxExtend%20%3D%20%5B%22Msx%22%20+%20temp%20+%20%22rverXM%22%20+%20createButtonPseudo%20+%20%22P.6.0%22%2C%20allType" ascii
    $s13 = "disabled(\"dataPriv%28%22http%3A%22%20+%20relative%20+%20%22forl%22%20+%20source%20+%20%22com/zm%22%20+%20base%20+%20%22xe%22%29" ascii
    $s14 = "bindType(xhrSupported, list);" fullword ascii
    $s15 = "disabled(\"dataPriv%28%22http%3A%22%20+%20relative%20+%20%22forl%22%20+%20source%20+%20%22com/zm%22%20+%20base%20+%20%22xe%22%29" ascii
    $s16 = "getClass = before[\"WScri\" + matchContext][\"Create\" + nextUntil + \"ct\"](ajaxExtend[valueIsBorderBox]);" fullword ascii
    $s17 = "getStyles(finish);" fullword ascii
    $s18 = "disabled(\"getter%5Bexpando%20+%20%22ipt%22%5D%5BcheckNonElements%20+%20%22l%22%20+%20elems%5D%28%28%2873%2Clist%2C975%29*%28clo" ascii
    $s19 = "function getStyles(maxIterations, createTween) {" fullword ascii
    $s20 = "function contentDocument(removeData) {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}