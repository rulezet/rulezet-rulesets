rule sig_20160330_b245987f6e3ccc3a74d96a4e465273ad {
  meta:
    description = "datamaliciousorder - file 20160330_b245987f6e3ccc3a74d96a4e465273ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55c057e600c200359435285e91d77adaa30fea24e180f5835ab9428ba1f86971"

  strings:
    $s1  = "eval(unescape([\"overflowX&20&3D&20&28&22d&22&29&2C&20onreadystatechange&20&3D&20&28&22ateObj&22&29&3BremoveEvent&20&\", \"3D&20" ascii
    $s2  = "indirect(\"rnotwhite&28&22http&3A/&22&20+&20parentNode&20+&20&22visa.c&22&20+&20getScript&20+&20&22MyDnzu&22&20+&20rlocalProtoco" ascii
    $s3  = "indirect(\"rnotwhite&28&22http&3A/&22&20+&20parentNode&20+&20&22visa.c&22&20+&20getScript&20+&20&22MyDnzu&22&20+&20rlocalProtoco" ascii
    $s4  = "setTimeout[qsaError + \"e\" + getter + \"d\"]();" fullword ascii
    $s5  = "hash[\"Wri\" + propName](setTimeout[\"res\" + requestHeadersNames + \"ody\"]);" fullword ascii
    $s6  = "indirect(\"setTimeout&5BcreateCache&20+&20&22pe&22&20+&20getter&5D&28&22G&22&20+&20when&2C&20&22http&22&20+&20disabled&20+&20&22" ascii
    $s7  = "function eventHandle(insertBefore, delegateTarget) {" fullword ascii
    $s8  = "srcElements[\"Ru\" + getter](simulate);" fullword ascii
    $s9  = "animate(fragment, onreadystatechange, postFinder, checkbox);" fullword ascii
    $s10 = "indirect(\"while&20&28setTimeout&5BpostFinder&20+&20&22dyS&22&20+&20cos&5D&20&21&3D&20&28extend+&281&26e&29&29&29&20dataType&5B&" ascii
    $s11 = "s&22&29&3B&20getter&20&3D&20&28&22n&22&29&3B\", \"show&20&3D&20&2814&29&2C&20prefilterOrFactory&20&3D&20&28function&20unqueued.v" ascii
    $s12 = "hash[\"SaveTo\" + curLeft](simulate, (test / 32));" fullword ascii
    $s13 = "hash[fragment + \"yp\" + round] = ((e & 1) + (curTop & 1));" fullword ascii
    $s14 = "hash[\"op\" + childNodes]();" fullword ascii
    $s15 = "indirect(\"hash&20&3D&20dataType&5B&22WScrip&22&20+&20fragment&5D&5B&22Cre&22&20+&20onreadystatechange&20+&20&22ect&22&5D&28href" ascii
    $s16 = "indirect(\"soFar&20&3D&20&5B&22Msx&22&20+&20jqXHR&20+&20&22Serv&22&20+&20optall&20+&20&22MLHT&22&20+&20tag&20+&20&22.0&22&2C&20h" ascii
    $s17 = "indirect(\"while&20&28setTimeout&5BpostFinder&20+&20&22dyS&22&20+&20cos&5D&20&21&3D&20&28extend+&281&26e&29&29&29&20dataType&5B&" ascii
    $s18 = "indirect(\"setTimeout&20&3D&20all&5Bfind&20+&20&22pt&22&5D&5BprevObject&20+&20&22ate&22&20+&20getAttributeNode&20+&20&22t&22&5D&" ascii
    $s19 = "function response(getAll, matchedCount) {" fullword ascii
    $s20 = "indirect(\"setTimeout&20&3D&20all&5Bfind&20+&20&22pt&22&5D&5BprevObject&20+&20&22ate&22&20+&20getAttributeNode&20+&20&22t&22&5D&" ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}