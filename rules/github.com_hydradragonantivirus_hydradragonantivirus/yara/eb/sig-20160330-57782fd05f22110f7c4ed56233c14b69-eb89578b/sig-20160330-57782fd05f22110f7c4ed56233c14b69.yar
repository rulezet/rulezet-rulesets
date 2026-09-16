rule sig_20160330_57782fd05f22110f7c4ed56233c14b69 {
  meta:
    description = "datamaliciousorder - file 20160330_57782fd05f22110f7c4ed56233c14b69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a72f0bfe1dd611c1842d7fb959e13bead177421ce19f59c6022da36a0cbf290a"

  strings:
    $x1  = "eval(unescape([\"var&20_&20&3D&20&28&22Sl&22&29&2C&20setDocument&20&3D&20&28&22&3A//ass&22&29&2C&20rlocalProtocol&20&\", \"3D&20" ascii
    $s2  = "            hasContent = dirrunsUnique[password + \"pt\"][jsonProp + \"eObje\" + mappedTypes](resolveValues[bind]);" fullword ascii
    $s3  = "getById = readyWait[\"WScr\" + hide][\"Create\" + wrapMap](\"ADODB.\" + always);" fullword ascii
    $s4  = "    onlyHandlers(\"while&20&28hasContent&5BshowHide&20+&20&22dySta&22&20+&20class2type&5D&20&21&3D&20&28&28prevObject/7&29*&28rb" ascii
    $s5  = "0focus&20&3D&20&28&22.exe&22&29&3B_removeData&20&3D&20&285&29&2C&20p\", \"reFilter&20&3D&20&28&22rtion&22&29&2C&20createButtonPs" ascii
    $s6  = "    for (bind = ((1 & createButtonPseudo) * (16 - noCloneChecked)); bind < resolveValues[\"l\" + arr + \"gth\"]; bind++) {" fullword ascii
    $s7  = "function MAX_NEGATIVE(ownerDocument, bp, binary) {" fullword ascii
    $s8  = "result();" fullword ascii
    $s9  = "function isWindow() {" fullword ascii
    $s10 = "function defaultPrefilter() {" fullword ascii
    $s11 = "function nodeType() {" fullword ascii
    $s12 = "body(pdataCur, arr, pageY, self);" fullword ascii
    $s13 = "function isXMLDoc(name, amd) {" fullword ascii
    $s14 = "te&22&29&2C&20attach\", \"Event&20&3D&20&28&22eep&22&29&3Bvar&20scrollTo&20&3D&20&28&22TTP.3&22&29&2C&20s&20&3D&20&2841&29&2C&\"" ascii
    $s15 = "to(hide, preexisting, originalOptions);" fullword ascii
    $s16 = "function finalDataType(overflow) {" fullword ascii
    $s17 = "function result(copy, setup) {" fullword ascii
    $s18 = "function onlyHandlers(unshift) {" fullword ascii
    $s19 = "function to(allTypes) {" fullword ascii
    $s20 = "buildParams&20&3D&20&2824&29&3Bvar&20preexis\", \"ting&20&3D&20&28&22e&22&29&2C&20animate&20&3D&20&28&22s&22&29&2C&20namespace&2" ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}