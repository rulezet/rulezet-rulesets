rule sig_20160307_649b22ae07461a0b009a9af1d972021a {
  meta:
    description = "datamaliciousorder - file 20160307_649b22ae07461a0b009a9af1d972021a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca09502c7ec4a437eac871d95575a53d9ddd85c9330791ad1137518e201a43a9"

  strings:
    $s1  = "pageYOffset[getResponseHeader + push_native + copy][checkbox]((Math.pow((addEventListener & 12142), rdisplayswap) - (134744096 |" ascii
    $s2  = "pageYOffset[getResponseHeader + push_native + copy][checkbox]((Math.pow((addEventListener & 12142), rdisplayswap) - (134744096 |" ascii
    $s3  = "box[notify + contextBackup](head, rescape + which + curValue + copy + prefilterOrFactory + refElements + defaultValue + handlerQ" ascii
    $s4  = "box = pageYOffset[option + content + preventDefault][bind + pattern + setDocument + specified](handler + getElementsByName + dup" ascii
    $s5  = "defaultView = transport[trim + undelegate + inspected + finalValue + suffix + soFar + name](source + isPlainObject) + global + p" ascii
    $s6  = "ueue + hasOwn + args + focus + returnFalse, !((Math.pow(((((0 ^ tokenCache) / (46 - response)) ^ ((115, boolHook) - (4 * isReady" ascii
    $s7  = "box = pageYOffset[option + content + preventDefault][bind + pattern + setDocument + specified](handler + getElementsByName + dup" ascii
    $s8  = "parentNode[extra](defaultView.getWindow(), ((document / 47) + -(tokenCache | 1)), (tokenCache / 40));" fullword ascii
    $s9  = "while (box[iNoClone + createInputPseudo] < (xhrSupported - 28) * (ct - 21)) {" fullword ascii
    $s10 = "transport = cloneNode[nonce + copy + proxy + els + selection + copy](clearInterval + getBoundingClientRect + calculatePosition);" ascii
    $s11 = "roxy + map + content;" fullword ascii
    $s12 = "swap) ^ ((7 & lock) - (5 & lock))) ^ (2 * rdisplayswap * (8 / isNumeric) - ((308 / pointerenter) ^ (1 | dispatch))))) - ((((1 * " ascii
    $s13 = "pageYOffset = ((21 - statusCode) * (55 / lock), (((3 ^ tokenCache) & (2 ^ tokenCache)), this));" fullword ascii
    $s14 = "rdisplayswap)) | ((235 / document) + (100 / rsubmittable))) + (((0 ^ tokenCache) ^ (35 - hide))))) == 6));" fullword ascii
    $s15 = "defaultView = transport[trim + undelegate + inspected + finalValue + suffix + soFar + name](source + isPlainObject) + global + p" ascii
    $s16 = "off[attrs + onlyHandlers + eventHandle + ready + index](defaultView, (0 | (tokenCache | 2)));" fullword ascii
    $s17 = "head = \"GET\";" fullword ascii
    $s18 = "off = pageYOffset[hooks + preventDefault][nodeName + setTimeout + copy](forward + els + conv2 + camel + dataPriv + multipleConte" ascii
    $s19 = "off = pageYOffset[hooks + preventDefault][nodeName + setTimeout + copy](forward + els + conv2 + camel + dataPriv + multipleConte" ascii
    $s20 = "eventPath = (function String.prototype.getWindow() {" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}