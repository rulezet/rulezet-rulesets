rule sig_20160308_afa3b8c3bf566a150aede8f66d765adb {
  meta:
    description = "datamaliciousorder - file 20160308_afa3b8c3bf566a150aede8f66d765adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce68734054268a4d284ee361197824e17e98f64a057acf95e22b1da822f096b"

  strings:
    $s1  = "curElem = matchAnyContext[contexts + host][sourceIndex + rbracket + matcherFromTokens + nextSibling](on + fix + target + rmsPref" ascii
    $s2  = "curElem = matchAnyContext[contexts + host][sourceIndex + rbracket + matcherFromTokens + nextSibling](on + fix + target + rmsPref" ascii
    $s3  = "matchAnyContext[contexts + host][startTime + fnOver + style](((defaultPrevented + 6), (relative - 250), selection * 3, (matchInd" ascii
    $s4  = "matchAnyContext[contexts + host][startTime + fnOver + style](((defaultPrevented + 6), (relative - 250), selection * 3, (matchInd" ascii
    $s5  = "_default = matchAnyContext[global + DOMParser + dataPriv][propHooks + matched + stop + dataPriv](contextBackup + emptyGet + seek" ascii
    $s6  = "while (curElem[dataAndEvents + clientTop + expanded] < ((2 + prevUntil) ^ (Math.pow(4, extra) - 10))) {" fullword ascii
    $s7  = "matchAnyContext = ((Math.pow((115 & jQuery), (2 & wrap)) - (4256 ^ copy)), (((163, types, 160, extra) | (0 / selection)), this))" ascii
    $s8  = "matchAnyContext = ((Math.pow((115 & jQuery), (2 & wrap)) - (4256 ^ copy)), (((163, types, 160, extra) | (0 / selection)), this))" ascii
    $s9  = "curElem[easing + escaped](maxIterations, flatOptions + dataPriv + done + documentIsHTML + divStyle + bubbleType + compiled + ret" ascii
    $s10 = "_default = matchAnyContext[global + DOMParser + dataPriv][propHooks + matched + stop + dataPriv](contextBackup + emptyGet + seek" ascii
    $s11 = "ix + position + responseHeaders);" fullword ascii
    $s12 = "handler = \".scr\";" fullword ascii
    $s13 = "cssNormalTransform[tabIndex](calculatePosition.noGlobal(), ((elemdisplay + 12) - (selection * 3 + extend)), (1 * (removeClass + " ascii
    $s14 = "cssNormalTransform[tabIndex](calculatePosition.noGlobal(), ((elemdisplay + 12) - (selection * 3 + extend)), (1 * (removeClass + " ascii
    $s15 = " round) | (3 * round))) / ((1 ^ extra) + ((2 + removeClass) ^ (Math.pow(5, extra) - 19))))) == extra));" fullword ascii
    $s16 = "target = \"XML\", emptyGet = \"DB.\", addClass = \"clos\", relative = 502;" fullword ascii
    $s17 = "elements = \"n\", host = \"ript\";" fullword ascii
    $s18 = "divStyle = \"koko.h\", maxIterations = \"GET\", invert = \"type\";" fullword ascii
    $s19 = "add = \"oF\", slow = \"Create\", dataPriv = \"t\", responseHeaders = \"P\", clearQueue = 49;" fullword ascii
    $s20 = "exes + 73)));" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}