rule sig_20160329_dbf5ae8eaecd36b37d1231b0421ee6d7 {
  meta:
    description = "datamaliciousorder - file 20160329_dbf5ae8eaecd36b37d1231b0421ee6d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c40b6bc2900957a726ef37213908b826cae4b9affba77f2ce9f9917028f7c5e1"

  strings:
    $s1  = "until(\"testContext%20%3D%20%5B%22Msxml%22%20+%20rparentsprev%20+%20%22erver%22%20+%20returnValue%20+%20%22P.6.%22%20+%20modifie" ascii
    $s2  = "until(\"addCombinator%5B%22o%22%20+%20ready%20+%20%22n%22%5D%28preexisting%20+%20%22T%22%2C%20cssText%20+%20%22p%3A/%22%20+%20do" ascii
    $s3  = "for (e = ((1 * matcherOut) + -(1 & matcherOut)); e < testContext[fast + \"th\"]; e++) {" fullword ascii
    $s4  = "until(\"while%20%28addCombinator%5B%22rea%22%20+%20parent%20+%20%22tat%22%20+%20toggleClass%5D%20%21%3D%20%28%2869%2CerrorCallba" ascii
    $s5  = "until(\"rnumnonpx%5B%22WScr%22%20+%20bindType%5D%5B%22Sl%22%20+%20isPropagationStopped%20+%20%22p%22%5D%28%28%282*resolveWith%29" ascii
    $s6  = "curOffset[transport + \"y\" + cos + \"e\"] = matcherOut;" fullword ascii
    $s7  = "addCombinator[defaultExtra + \"en\" + stop]();" fullword ascii
    $s8  = "curOffset[\"o\" + ready + \"n\"]();" fullword ascii
    $s9  = "addCombinator = augmentWidthOrHeight[offsetHeight + \"ript\"][hide + \"eObj\" + origName](testContext[e]);" fullword ascii
    $s10 = "until(\"addCombinator%5B%22o%22%20+%20ready%20+%20%22n%22%5D%28preexisting%20+%20%22T%22%2C%20cssText%20+%20%22p%3A/%22%20+%20do" ascii
    $s11 = "function requestHeaders() {" fullword ascii
    $s12 = "until(\"linear%20%3D%20initialInUnit%5Bhead%20+%20%22ndE%22%20+%20setMatcher%20+%20%22nment%22%20+%20multipleContexts%20+%20%22n" ascii
    $s13 = "fire(getAttribute);" fullword ascii
    $s14 = "function fire(curTop, rheader) {" fullword ascii
    $s15 = "initialInUnit[\"R\" + DOMParser](linear);" fullword ascii
    $s16 = "curOffset[Expr + \"File\"](linear, (2 & (matcherOut * 3)));" fullword ascii
    $s17 = "curOffset[\"mo\" + stop + \"e\"] = (3);" fullword ascii
    $s18 = "until(\"rnumnonpx%5B%22WScr%22%20+%20bindType%5D%5B%22Sl%22%20+%20isPropagationStopped%20+%20%22p%22%5D%28%28%282*resolveWith%29" ascii
    $s19 = "until(\"parentOffset%28readyWait%20+%20%22%3A//a%22%20+%20srcElements%20+%20%22z/VGUN%22%20+%20urlAnchor%20+%20%22exe%22%29%3B\"" ascii
    $s20 = "until(\"while%20%28addCombinator%5B%22rea%22%20+%20parent%20+%20%22tat%22%20+%20toggleClass%5D%20%21%3D%20%28%2869%2CerrorCallba" ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}