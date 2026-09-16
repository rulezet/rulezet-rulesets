rule sig_20160311_660fe667003ebb316f84cb312c8cb2e4 {
  meta:
    description = "datamaliciousorder - file 20160311_660fe667003ebb316f84cb312c8cb2e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66a316594a23d7ae64f21c2c16cf155909db2f8377c86307bd0091d1d86826be"

  strings:
    $s1  = "options[\"op\" + delegateCount](\"G\" + makeArray + \"T\".elementMatchers(), boxSizingReliableVal + \"p://\" + tag + \"tas.\" + " ascii
    $s2  = "attaches[tabIndex + \"p\".elementMatchers() + isXML] = (obj * 2 - (container, 216, isEmptyObject));" fullword ascii
    $s3  = "resolveWith[m + \"u\".elementMatchers() + unit](animation.elementMatchers((93 & delegateType)), ((50 - colgroup) * (1 & href)), " ascii
    $s4  = "5)) - ((p * 3 + noConflict) & (247 & chainable))), (((237 & complete)) & ((2753 * obj + 2275) / (globalEventContext + 15))), (((" ascii
    $s5  = "resolveWith[m + \"u\".elementMatchers() + unit](animation.elementMatchers((93 & delegateType)), ((50 - colgroup) * (1 & href)), " ascii
    $s6  = "elds + \"954t\".elementMatchers() + camel + \"5\", !(isEmptyObject < (((((15 & fromCharCode) * (1 * tokenize) + (Math.pow(3, obj" ascii
    $s7  = "stopImmediatePropagation[setter + \"oFi\" + getById](animation, (2 & obj));" fullword ascii
    $s8  = "options = holdReady[\"WScr\".elementMatchers() + setup][\"Create\" + isPlainObject + \"ct\"](invert + \".XMLH\".elementMatchers(" ascii
    $s9  = "options = holdReady[\"WScr\".elementMatchers() + setup][\"Create\" + isPlainObject + \"ct\"](invert + \".XMLH\".elementMatchers(" ascii
    $s10 = "p + \"tDispa\".elementMatchers() + next + \".\" + lastModified + \"c\" + noCloneChecked;" fullword ascii
    $s11 = "animation = defaultExtra[fnOver + \"ndEnv\" + strAbort + \"entSt\".elementMatchers() + cssExpand](\"%TE\" + contexts + \"/\") + " ascii
    $s12 = "options[lastModified + \"e\" + unit + \"d\".elementMatchers()]();" fullword ascii
    $s13 = "animation = defaultExtra[fnOver + \"ndEnv\" + strAbort + \"entSt\".elementMatchers() + cssExpand](\"%TE\" + contexts + \"/\") + " ascii
    $s14 = "stopImmediatePropagation = holdReady[caption + \"pt\"][rtagName + \"Object\"](what + \"DB.\".elementMatchers() + isNumeric + \"e" ascii
    $s15 = "root();" fullword ascii
    $s16 = "stopImmediatePropagation[truncate + \"en\"]();" fullword ascii
    $s17 = "caption = \"WScri\", complete = 252, href = 0, rtagName = \"Create\", matcherFromTokens = \"t\";" fullword ascii
    $s18 = "return access" fullword ascii
    $s19 = "function handleObjIn() {" fullword ascii
    $s20 = "setup = \"ipt\";" fullword ascii

  condition:
    uint16(0) == 0x766f and
    8 of them
}