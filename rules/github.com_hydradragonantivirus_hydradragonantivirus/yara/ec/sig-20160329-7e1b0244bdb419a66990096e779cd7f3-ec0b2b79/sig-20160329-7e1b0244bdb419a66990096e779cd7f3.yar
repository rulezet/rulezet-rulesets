rule sig_20160329_7e1b0244bdb419a66990096e779cd7f3 {
  meta:
    description = "datamaliciousorder - file 20160329_7e1b0244bdb419a66990096e779cd7f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fe7ee7de0936f85fcd51c3725d662771cc9c91da9ea367991508c30e34c5e27"

  strings:
    $s1  = "clone(\"noop%5BcssHooks%20+%20%22en%22%5D%28idx%20+%20%22E%22%20+%20xhrSuccessStatus%2C%20%22http%3A/%22%20+%20code%20+%20%22kin" ascii
    $s2  = "cur[\"mo\" + _removeData + \"e\"] = (14 - target);" fullword ascii
    $s3  = "dataTypeOrTransport = temp = getAttribute = rmultiDash = ajax.after();" fullword ascii
    $s4  = "noop[\"se\" + content]();" fullword ascii
    $s5  = "function now(opacity, t, password) {" fullword ascii
    $s6  = "cur[nType + \"pe\"] = ((84 - swap) - (40 | current));" fullword ascii
    $s7  = "clone(\"div%20%3D%20temp%5B%22WSc%22%20+%20augmentWidthOrHeight%5D%5B%22Create%22%20+%20removeEvent%20+%20%22t%22%5D%28setOffset" ascii
    $s8  = "for(fixInput = (1 + -(add - 32)); fixInput < classNames[\"le\" + token]; fixInput++) {" fullword ascii
    $s9  = "clone(\"div%20%3D%20temp%5B%22WSc%22%20+%20augmentWidthOrHeight%5D%5B%22Create%22%20+%20removeEvent%20+%20%22t%22%5D%28setOffset" ascii
    $s10 = "function getResponseHeader() {" fullword ascii
    $s11 = "function thead(detach, div1, domManip) {" fullword ascii
    $s12 = "cur[isHidden + \"te\"](noop[height + \"nseBo\" + overflowX]);" fullword ascii
    $s13 = "clone(\"while%20%28noop%5B%22rea%22%20+%20document%20+%20%22ate%22%5D%20%21%3D%20%28%281+copyIsArray%29*2%29%29%20rmultiDash%5Bs" ascii
    $s14 = "clone(\"rmultiDash%5B%22WScri%22%20+%20grep%5D%5B%22Sleep%22%5D%28%28%28unloadHandler%29%2C%2825*bind+18%29%2C%28rsingleTag*5*rs" ascii
    $s15 = "clone(\"rmultiDash%5B%22WScri%22%20+%20grep%5D%5B%22Sleep%22%5D%28%28%28unloadHandler%29%2C%2825*bind+18%29%2C%28rsingleTag*5*rs" ascii
    $s16 = "clone(\"MAX_NEGATIVE%20%3D%20div%5B%22Exp%22%20+%20XMLHttpRequest%20+%20%22nviron%22%20+%20s%20+%20%22tStrin%22%20+%20contextBac" ascii
    $s17 = "clone(\"noop%5BcssHooks%20+%20%22en%22%5D%28idx%20+%20%22E%22%20+%20xhrSuccessStatus%2C%20%22http%3A/%22%20+%20code%20+%20%22kin" ascii
    $s18 = "noop = dataTypeOrTransport[\"WSc\" + augmentWidthOrHeight][\"Creat\" + offsetHeight + \"t\"](classNames[fixInput]);" fullword ascii
    $s19 = "function mouseenter(animation, iframe, original) {" fullword ascii
    $s20 = "clone(\"MAX_NEGATIVE%20%3D%20div%5B%22Exp%22%20+%20XMLHttpRequest%20+%20%22nviron%22%20+%20s%20+%20%22tStrin%22%20+%20contextBac" ascii

  condition:
    uint16(0) == 0x696c and
    8 of them
}