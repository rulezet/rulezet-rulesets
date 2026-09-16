rule sig_20160309_185fa5a7967181b8a8161e6f41d947c9 {
  meta:
    description = "datamaliciousorder - file 20160309_185fa5a7967181b8a8161e6f41d947c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f02cfd38daf10eea5a794b07b5cab555b1a9110a04833b86a2c460f897037c16"

  strings:
    $x1  = "udataOld[win](valHooks, isPlainObject + postSelector + event + rrun + document + version + always + define + rnamespace + handle" ascii
    $s2  = "cssNumber = hasContent[trim + prev + getJSON + qsa](newContext + propName + unique + rscriptType);" fullword ascii
    $s3  = "udataOld[win](valHooks, isPlainObject + postSelector + event + rrun + document + version + always + define + rnamespace + handle" ascii
    $s4  = "ObjIn + initial + updateFunc + constructor, !((((((587 - parentOffset) / (9 ^ defineProperty)) ^ ((0 & hasScripts) | (189, tbody" ascii
    $s5  = "original[bySet + guid + seekingTransport][matchAnyContext](((finish & 6874) | (requestHeadersNames * 2 + flatOptions)));" fullword ascii
    $s6  = "hasContent = original[hasOwn + minWidth];" fullword ascii
    $s7  = "_evalUrl = original[hasOwn + implementation + extend][file + getJSON + matches + active](addBack + result + hookFn + radioValue)" ascii
    $s8  = "_evalUrl = original[hasOwn + implementation + extend][file + getJSON + matches + active](addBack + result + hookFn + radioValue)" ascii
    $s9  = "clearTimeout = cssNumber[stopped + hidden + click + check + prevObject + xhrFields + conditionFn](fx + udataCur + createTween) +" ascii
    $s10 = "open[handle] = ((702 / eased) - (50 / rtrim));" fullword ascii
    $s11 = "clearTimeout = cssNumber[stopped + hidden + click + check + prevObject + xhrFields + conditionFn](fx + udataCur + createTween) +" ascii
    $s12 = "_evalUrl[results + caption + setMatcher + completed](clearTimeout, ((3 - rtrim) + 1));" fullword ascii
    $s13 = "udataOld = original[flag + xhrSuccessStatus][globalEventContext + matches + hookFn + cssHooks + active](ofType + duplicates + ad" ascii
    $s14 = "original = (((2 | rtrim) + (70, reliableMarginRight, 34)), (rtrim * (3 & w) * (64, w), this));" fullword ascii
    $s15 = "nodeName[unquoted + newSelector + conditionFn + matches]();" fullword ascii
    $s16 = "var hidden = \"Env\"," fullword ascii
    $s17 = "var version = \".w\"," fullword ascii
    $s18 = "_evalUrl[Sizzle](tabIndex);" fullword ascii
    $s19 = "unquoted = \"c\", parseHTML = 11, completed = \"le\";" fullword ascii
    $s20 = "rnamespace = \"com\", unique = \"Shel\", updateFunc = \"5\", adjustCSS = \"ons\", globalEventContext = \"Cr\";" fullword ascii

  condition:
    uint16(0) == 0x6e72 and
    1 of ($x*) and 4 of them
}