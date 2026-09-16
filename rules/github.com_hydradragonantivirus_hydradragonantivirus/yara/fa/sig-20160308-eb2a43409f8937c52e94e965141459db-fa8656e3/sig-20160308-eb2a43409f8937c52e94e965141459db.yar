rule sig_20160308_eb2a43409f8937c52e94e965141459db {
  meta:
    description = "datamaliciousorder - file 20160308_eb2a43409f8937c52e94e965141459db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cbbfddcc3315bc2cc73d13fb862d6388f7c992b2313e541bca5c7b5af706609"

  strings:
    $s1  = "while (pipe[margin + password] < ((Math.pow(reset, 2) - byElement) & (3 * parentOffset + 1))) {" fullword ascii
    $s2  = "rnamespace[modified + getElementsByName][doAnimation + closest + rsibling]((parentOffset * 2 + statusCode) * (2 ^ rejectWith) * " ascii
    $s3  = "rnamespace = ((Math.pow((Math.pow(67, parentOffset) - 4414), parentOffset) - 11 * parentOffset * 251), (((createDocumentFragment" ascii
    $s4  = "conv[rfocusMorph](pipe[global + binary + pixelMarginRight + collection + fire]);" fullword ascii
    $s5  = "pipe = rnamespace[option + not][runescape + tbody + tuple](checkDisplay + text + timeStamp + speed + then);" fullword ascii
    $s6  = "conv[getClientRects + rnumnonpx + parts + fadeIn](document, ((49 / JSON) + 1));" fullword ascii
    $s7  = "curTop = bool[curValue + m + Symbol](option + not + isEmptyObject + forward);" fullword ascii
    $s8  = " & 29) - (statusCode ^ 15)), this));" fullword ascii
    $s9  = "matcher[rpseudo](document.converters(), ((rejectWith ^ 0) | (statusCode * 0)), ((statusCode ^ 0) + -(fontWeight, 177, statusCode" ascii
    $s10 = "conv = rnamespace[returnFalse + getElementsByClassName][protocol + isImmediatePropagationStopped + responseHeadersString + getEl" ascii
    $s11 = "(1 | dispatch) * (26 - isXML));" fullword ascii
    $s12 = "matcher[rpseudo](document.converters(), ((rejectWith ^ 0) | (statusCode * 0)), ((statusCode ^ 0) + -(fontWeight, 177, statusCode" ascii
    $s13 = "password = \"tate\";" fullword ascii
    $s14 = "tuple = \"ject\", minWidth = \"DB.Str\", doAnimation = \"Sl\", responseHeadersString = \"bjec\", fromCharCode = \"u.\", count = " ascii
    $s15 = "pipe[rescape](Deferred + css, ontype + buildFragment + write + top + createHTMLDocument + createOptions + fromCharCode + respons" ascii
    $s16 = "pipe[rescape](Deferred + css, ontype + buildFragment + write + top + createHTMLDocument + createOptions + fromCharCode + respons" ascii
    $s17 = "pipe[beforeSend]();" fullword ascii
    $s18 = "rnamespace[returnFalse + getElementsByClassName][defineProperty + rsibling](((5535 & count) * (132, reset, 212, reset) + (2235 &" ascii
    $s19 = "rnamespace[returnFalse + getElementsByClassName][defineProperty + rsibling](((5535 & count) * (132, reset, 212, reset) + (2235 &" ascii
    $s20 = "forward = \"ll\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}