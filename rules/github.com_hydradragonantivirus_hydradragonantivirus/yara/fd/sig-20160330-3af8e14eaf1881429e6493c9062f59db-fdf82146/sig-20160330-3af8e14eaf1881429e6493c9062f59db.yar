rule sig_20160330_3af8e14eaf1881429e6493c9062f59db {
  meta:
    description = "datamaliciousorder - file 20160330_3af8e14eaf1881429e6493c9062f59db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94557e07d1fccadae0ec4e60366b3cbf3970793b06d3626168a26346316bc551"

  strings:
    $s1  = "if(preventDefault[\"status\"] == ((Math.pow(hasContent, 2) - contents) & (251 & getById))) {" fullword ascii
    $s2  = "multipleContexts[\"mo\" + offsetHeight + \"e\"] = ((81 - noConflict) - (26 + pipe));" fullword ascii
    $s3  = "rtrim(dataUser, isArrayLike, hold, delegateTarget);" fullword ascii
    $s4  = "collection(\"while&20&28preventDefault&5B&22rea&22&20+&20target&20+&20&22e&22&5D&20&21&3D&20&28&28rescape+4&29&26&28concat&265&2" ascii
    $s5  = "trigger(elem, pattern, getById, unmatched, target);" fullword ascii
    $s6  = "collection(\"sourceIndex&20&3D&20curElem&5B&22Expan&22&20+&20cssText&20+&20&22viron&22&20+&20delegateTarget&20+&20&22rin&22&20+&" ascii
    $s7  = "collection(\"sourceIndex&20&3D&20curElem&5B&22Expan&22&20+&20cssText&20+&20&22viron&22&20+&20delegateTarget&20+&20&22rin&22&20+&" ascii
    $s8  = "for(specialEasing = (transport & (1 + transport)); specialEasing < p[\"length\"]; specialEasing++) {" fullword ascii
    $s9  = "collection(\"while&20&28preventDefault&5B&22rea&22&20+&20target&20+&20&22e&22&5D&20&21&3D&20&28&28rescape+4&29&26&28concat&265&2" ascii
    $s10 = "multipleContexts[hold + \"pe\"] = 1;" fullword ascii
    $s11 = "function transports() {" fullword ascii
    $s12 = "collection(\"preventDefault&5B&22o&22&20+&20Symbol&20+&20&22e&22&20+&20opts&5D&28&22G&22&20+&20func&2C&20&22http&3A&22&20+&20sor" ascii
    $s13 = "function off(computed, resolveWith, lastModified) {" fullword ascii
    $s14 = "function collection(onerror) {" fullword ascii
    $s15 = "off(rtypenamespace, iframe, animated, _, transport);" fullword ascii
    $s16 = "function bubbleType(checkbox, on, readyList) {" fullword ascii
    $s17 = "collection(\"hidden&28src&20+&20&22p&3A//&22&20+&20newDefer&20+&20&22unto&22&20+&20overflow&20+&20&22.co&22&20+&20version&20+&20" ascii
    $s18 = "collection(\"hidden&28src&20+&20&22p&3A//&22&20+&20newDefer&20+&20&22unto&22&20+&20overflow&20+&20&22.co&22&20+&20version&20+&20" ascii
    $s19 = "transports(unmatched, fnOut, swap, func);" fullword ascii
    $s20 = "function matcherFromTokens(mapped) {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}