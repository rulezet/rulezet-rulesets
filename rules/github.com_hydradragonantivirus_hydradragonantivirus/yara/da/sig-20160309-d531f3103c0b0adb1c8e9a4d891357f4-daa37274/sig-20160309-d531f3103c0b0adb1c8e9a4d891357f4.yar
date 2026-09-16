rule sig_20160309_d531f3103c0b0adb1c8e9a4d891357f4 {
  meta:
    description = "datamaliciousorder - file 20160309_d531f3103c0b0adb1c8e9a4d891357f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb3f584044ac5e8269084b8db2e201348ddb3891dc7353ee7005e3cd20f3688a"

  strings:
    $s1  = "max[createPositionalPseudo + pointerleave](delegateType + newDefer, focusin + tween + matcher + old + getElementsByClassName + b" ascii
    $s2  = "when[contexts + superMatcher][easing]((Math.pow((postFilter - 1109), rejectWith) - (50452096 ^ bindType)));" fullword ascii
    $s3  = "940 / pipe), (Math.pow(136, rejectWith) - 18305), detach) & (0 | rejectWith)))) == 9));" fullword ascii
    $s4  = "xhrFields[border](stop.headers(), ((39 & orig) - 13 * detach), 0);" fullword ascii
    $s5  = "proxy[adown + ajaxPrefilter](stop, ((round + -1) | (rejectWith & 3)));" fullword ascii
    $s6  = "  parents = \"%TEMP%\"," fullword ascii
    $s7  = "))) + ((((tweens | 202), (orig * 2 + rejectWith), (236 & rmsPrefix)), (1 * detach)) * ((33 - responseType) + (0 ^ round)) + (((2" ascii
    $s8  = "when = ((Math.pow((Math.pow(130, rejectWith) - 16676), rejectWith) - (1697450 / hide)), (((23 - converters) * (120, not, 0, reje" ascii
    $s9  = "tokenCache = fixInput[dataShow + requestHeadersNames + createOptions + calculatePosition + origFn + firingIndex](hover + firingI" ascii
    $s10 = "transports[removeAttr + wrapInner] = (1 * (round + -1));" fullword ascii
    $s11 = "when = ((Math.pow((Math.pow(130, rejectWith) - 16676), rejectWith) - (1697450 / hide)), (((23 - converters) * (120, not, 0, reje" ascii
    $s12 = "whitespace = max[defineProperty + completed + transport + createElement];" fullword ascii
    $s13 = "max = when[nativeStatusText + rtagName + firingIndex][to + val + originalSettings + firingIndex](insertBefore + matchExpr + box " ascii
    $s14 = "tokenCache = fixInput[dataShow + requestHeadersNames + createOptions + calculatePosition + origFn + firingIndex](hover + firingI" ascii
    $s15 = "p + tweener + map + indirect + setFilters + charCode + attrId + keys, !(((((1 * innerText) | 0) ^ ((innerText / 43) | (round * 1" ascii
    $s16 = "proxy[udataCur + events + val](whitespace);" fullword ascii
    $s17 = "proxy = when[nativeStatusText + rtagName + firingIndex][dataShow + nodeIndex + bp + idx + origType + disconnectedMatch](selectio" ascii
    $s18 = "proxy = when[nativeStatusText + rtagName + firingIndex][dataShow + nodeIndex + bp + idx + origType + disconnectedMatch](selectio" ascii
    $s19 = "disconnectedMatch = \"ject\", nodeIndex = \"ea\", events = \"it\", propFix = \"Expa\", charCode = \"f43\", pipe = 12;" fullword ascii
    $s20 = "stop = tokenCache[propFix + disable + escaped + s + checkDisplay + rmargin + progressValues](parents + isSuccess) + protocol + i" ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}