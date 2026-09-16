rule sig_20160307_62c3c609502da801eaea91e583e63be4 {
  meta:
    description = "datamaliciousorder - file 20160307_62c3c609502da801eaea91e583e63be4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adf625da013c47ec9caba5826296cf7c59619c42a316d0b03b0df1f7c45bee18"

  strings:
    $s1  = "fx[suffix + delegateCount](getScript, dataFilter + pixelMarginRightVal + getJSON + soFar + hasClass + stopQueue + inArray + refE" ascii
    $s2  = "on[checkClone + firingIndex + isDefaultPrevented + src][head + isDefaultPrevented]((Math.pow(replaceAll, 2) - col) * (0 | return" ascii
    $s3  = "matchContext = \"eObjec\", getScript = \"GET\", simple = \"Obje\", optionSet = 22, hover = \"%\", computed = \"HTTP\";" fullword ascii
    $s4  = "lements + done + propFilter + percent, !((Math.pow((((2 * getWindow - 23 * returnTrue) | (2 * returnTrue + 1))), ((((cur ^ 220)," ascii
    $s5  = "on[checkClone + firingIndex + isDefaultPrevented + src][head + isDefaultPrevented]((Math.pow(replaceAll, 2) - col) * (0 | return" ascii
    $s6  = "58), (Math.pow(globalEventContext, 2) - postDispatch), (0 | optionSet)) - (Math.pow((7 & easing), (0 | returnTrue)) - (361 / swi" ascii
    $s7  = "trigger[bind](fireWith.dispatch(), ((event | 0) * (onreadystatechange ^ 0)), (onreadystatechange ^ (1 + -event)));" fullword ascii
    $s8  = "on = ((1 | event), ((Math.pow((3 + event), (2 ^ onreadystatechange)) - (2 | seed)), this));" fullword ascii
    $s9  = " (Math.pow(expanded, 2) - siblingCheck), (170 | oldfire), (15 + timeStamp)) / ((15 * returnTrue + 3) + (progressValues - 45))) *" ascii
    $s10 = "fx[suffix + delegateCount](getScript, dataFilter + pixelMarginRightVal + getJSON + soFar + hasClass + stopQueue + inArray + refE" ascii
    $s11 = "on[end + noBubble][head + isDefaultPrevented](((assert / 3) ^ (access | 13440)));" fullword ascii
    $s12 = "fireWith = _removeData[classNames + origCount + returnValue + pos + src + rheader + elemLang + holdReady + evt](hover + s + cssP" ascii
    $s13 = "rfocusMorph[clearCloneStyle + matched + isSuccess](fireWith, ((event | 1) + (timeStamp - 25)));" fullword ascii
    $s14 = "fx = on[end + noBubble][detach + clientY + src + matchContext + src](contentType + cached + computed);" fullword ascii
    $s15 = "fireWith = _removeData[classNames + origCount + returnValue + pos + src + rheader + elemLang + holdReady + evt](hover + s + cssP" ascii
    $s16 = "while (fx[clientY + onlyHandlers + contexts + _data] < (returnTrue - 0) * (returnTrue & 3)) {" fullword ascii
    $s17 = "_removeData = tick[click + proxy + animation + isPlainObject + src](matchers + reliableMarginLeftVal + init + init);" fullword ascii
    $s18 = "mentsByName) & (206 - compilerCache)), ((251 & uniqueID) & (5 | abort)), ((2 * easing + 1) - (contains & 12))) ^ (((rsibling & 1" ascii
    $s19 = "True) * 5 * (onreadystatechange | 2));" fullword ascii
    $s20 = "head = \"Slee\", elemLang = \"trin\", err = \"WScri\";" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}