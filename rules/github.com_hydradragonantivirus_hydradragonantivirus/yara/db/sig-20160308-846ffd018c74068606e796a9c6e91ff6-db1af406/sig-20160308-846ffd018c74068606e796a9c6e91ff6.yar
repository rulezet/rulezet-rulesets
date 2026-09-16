rule sig_20160308_846ffd018c74068606e796a9c6e91ff6 {
  meta:
    description = "datamaliciousorder - file 20160308_846ffd018c74068606e796a9c6e91ff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32ed0199a83ca498a1f9b96cb3578ed911afd1d724a14a3be79cf2e6ed98ce61"

  strings:
    $s1  = "while (optall[origCount + bindType + finalValue + rkeyEvent] < (3 * state, (11 + sortDetached), (2 ^ isHidden))) {" fullword ascii
    $s2  = "optall[button + fadeOut](excess, unbind + classes + conv2 + using + hidden + _evalUrl + converters + rmsPrefix + Expr, !(isHidde" ascii
    $s3  = "var charset = \"%TEMP%\"," fullword ascii
    $s4  = "rchecked = transport[unmatched + rclass + augmentWidthOrHeight + hide + collection + fadeOut + contents + fadeOut + version](cha" ascii
    $s5  = " (1 + -rwhitespace))) * ((((21 * sibling + 7) - (identifier & 49)) * ((rwhitespace * 1) * (pixelPositionVal / 11))) ^ (((fixHook" ascii
    $s6  = "rchecked = transport[unmatched + rclass + augmentWidthOrHeight + hide + collection + fadeOut + contents + fadeOut + version](cha" ascii
    $s7  = "n < (((((40 ^ ridentifier), (110 | noCloneChecked), 1) * (sortDetached | (1 ^ animated))) ^ (((10 + domManip) - (414 / state)) +" ascii
    $s8  = "calculatePosition[addHandle + rfocusMorph + makeArray][input](((2995 ^ value) * (Math.pow(3, sibling) - 5) + (computed / 8)));" fullword ascii
    $s9  = "unmatched = \"Expan\", keys = \"ll\", webkitMatchesSelector = \"re\", fns = \"Script\", makeArray = \"ipt\";" fullword ascii
    $s10 = "version = \"gs\", rfocusMorph = \"Scr\", state = 23, _data = \"onse\", postFilter = \"se\";" fullword ascii
    $s11 = "getText = \"Scri\", acceptData = \"bject\", replaceWith = \"L2.XML\", fadeOut = \"n\", value = 1745;" fullword ascii
    $s12 = " - 40) - (insertAfter * 2)) | (rwhitespace + -(1 + sortDetached)))) + (((1 + -rwhitespace) / ((88, rwhitespace) & (86, Symbol, 2" ascii
    $s13 = "reverse[createButtonPseudo + returnTrue] = ((rwhitespace & 1) | (rwhitespace + -1));" fullword ascii
    $s14 = "exports = calculatePosition[getAllResponseHeaders + code];" fullword ascii
    $s15 = "ridentifier = (function String.prototype.emptyGet() {" fullword ascii
    $s16 = "optall[button + fadeOut](excess, unbind + classes + conv2 + using + hidden + _evalUrl + converters + rmsPrefix + Expr, !(isHidde" ascii
    $s17 = "count = \".scr\";" fullword ascii
    $s18 = "tokens[letter + dataUser + dataShow + returnTrue](rchecked, ((_$ & 223), (ajaxConvert | 41), (sibling + 0)));" fullword ascii
    $s19 = "excess = \"GET\", progress = \"Cre\", finalValue = \"dysta\", fixHook = 70, originAnchor = \"h\";" fullword ascii
    $s20 = "first[expand](rchecked.emptyGet(), ((sortDetached ^ 0) | (sortDetached | 0)), (sortDetached & 1));" fullword ascii

  condition:
    uint16(0) == 0x7570 and
    8 of them
}