rule sig_20160309_b25df2675ebc903217af158bca9a5b1e {
  meta:
    description = "datamaliciousorder - file 20160309_b25df2675ebc903217af158bca9a5b1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9f6682e08786d5d4c3848eb2b3245a75aa4ec072818b27c0e2a17152c4e8d9"

  strings:
    $s1  = "returnTrue[anim + getWidthOrHeight][find + preventDefault](((4694 ^ pipe) + (482 ^ showHide)));" fullword ascii
    $s2  = "getElementById[fire](writable, isHidden + risSimple + addHandle + Callbacks + postSelector + callbackInverse + cors + implementa" ascii
    $s3  = "bind[elemdisplay + win] = ((slow, 48) / (Math.pow(nativeStatusText, 2) - cos));" fullword ascii
    $s4  = "returnTrue = (((476 / namespaces) * (7 - hasOwn) + (16 - hash)), (((1 * parentWindow) + (1 + url)), this));" fullword ascii
    $s5  = " (nodeType + 40), (etag | 0)) | ((lang ^ 0))) & (((hash - 4) / (etag | 2)) ^ ((fn - 3) * (old - 27))))) - ((((dest | 0) + (args," ascii
    $s6  = "e, 2) - memory), 3 * lang * 3 * nodeType, (212 - rsubmittable)) / ((183, lang, 96) / lang)), (1 ^ nodeType)) - ((Math.pow((8 & b" ascii
    $s7  = "removeClass = preexisting[run + hasClass + markFunction](fireWith + notifyWith + global + getter);" fullword ascii
    $s8  = "responses = \".Strea\", initial = \"tStrin\", url = 14, ap = \"dy\", ajaxConvert = \"log\", run = \"Create\";" fullword ascii
    $s9  = "uniqueCache = returnTrue[apply + button][run + _load + computed + markFunction](cssExpand + eq + contexts + responses + rcombina" ascii
    $s10 = "uniqueCache = returnTrue[apply + button][run + _load + computed + markFunction](cssExpand + eq + contexts + responses + rcombina" ascii
    $s11 = " pipe = 3140," fullword ascii
    $s12 = "document[hasScripts]();" fullword ascii
    $s13 = "getElementById = returnTrue[apply + risSimple + elemdisplay][parse + createButtonPseudo + teardown](_default + camelCase + statu" ascii
    $s14 = "getElementById = returnTrue[apply + risSimple + elemdisplay][parse + createButtonPseudo + teardown](_default + camelCase + statu" ascii
    $s15 = "getElementById[fire](writable, isHidden + risSimple + addHandle + Callbacks + postSelector + callbackInverse + cors + implementa" ascii
    $s16 = " getter = \"ell\";" fullword ascii
    $s17 = "var writable = \"GET\"," fullword ascii
    $s18 = "dataTypeExpression[visibility + rfocusable] = (1 * etag);" fullword ascii
    $s19 = "tweeners = removeClass[checkClone + createTween + overflowX + initial + bindType](wrapAll + propHooks + curOffset + step) + fade" ascii
    $s20 = "tweeners = removeClass[checkClone + createTween + overflowX + initial + bindType](wrapAll + propHooks + curOffset + step) + fade" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}