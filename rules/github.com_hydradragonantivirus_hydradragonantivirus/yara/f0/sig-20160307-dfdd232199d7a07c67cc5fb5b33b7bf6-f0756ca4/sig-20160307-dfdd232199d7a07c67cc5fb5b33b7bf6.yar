rule sig_20160307_dfdd232199d7a07c67cc5fb5b33b7bf6 {
  meta:
    description = "datamaliciousorder - file 20160307_dfdd232199d7a07c67cc5fb5b33b7bf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b40ba04a8c5fd41894f7cb7d422246a888db7853b379994582587e52269a9de1"

  strings:
    $s1  = "isReady[contexts](write, elements + opt + defaultPrevented + defaultPrevented + marginLeft + fn + marginLeft + stateVal + boxSiz" ascii
    $s2  = "hash[responseText + to] = ((manipulationTarget + 107), (valHooks + 23), (elemData + -1));" fullword ascii
    $s3  = "while(isReady[jQuery + contentDocument + specified + hold + globalEventContext] < ((81 - get) - 7 * focusin * 2)) {" fullword ascii
    $s4  = "clearTimeout = rnotwhite[currentTime + origType + urlAnchor + isNumeric + mouseenter + curOffset + namespaces](image + tweeners " ascii
    $s5  = "booleans = (((67 & getElementById) ^ (646 - a)), (((588 / dirruns) - (8 | subordinate)), this));" fullword ascii
    $s6  = ", (Math.pow((click - 151), (elemData * 2)) - (mappedTypes - 6336)), (detach * 3 * detach * 3 ^ (curValue + 9)), ((rnoContent - 1" ascii
    $s7  = "rCode, 2) - getAttribute) + (100 - arg))), (((308 / class2type) + 1) - ((condense / 13) & (Math.pow(createComment, 2) - last))))" ascii
    $s8  = "isReady = booleans[rsubmitterTypes + curTop][nType + matcher + rattributeQuotes + queue](src + textContent + replaceAll + tweene" ascii
    $s9  = "isReady = booleans[rsubmitterTypes + curTop][nType + matcher + rattributeQuotes + queue](src + textContent + replaceAll + tweene" ascii
    $s10 = "isTrigger[marginLeft + amd](isReady[addGetHookIf + name + curElem + clientY + contains + eq + ajax]);" fullword ascii
    $s11 = "isTrigger = booleans[nodeName + iterator][relative + rkeyEvent + converters](inspectPrefiltersOrTransports + clone + noop + afte" ascii
    $s12 = "isTrigger = booleans[nodeName + iterator][relative + rkeyEvent + converters](inspectPrefiltersOrTransports + clone + noop + afte" ascii
    $s13 = "booleans[optionSet + oMatchesSelector][realStringObj + rclickable]((Math.pow((_jQuery, 148, acceptData), (2 & detach)) - (Math.p" ascii
    $s14 = " - (((66 | click) + (Math.pow(1667, focusin) - 2776196)) + ((els * 4 + modified)))) / ((((99, beforeSend, 34) + (dataAttr - 48))" ascii
    $s15 = "ingReliableVal + unmatched + nodeType + rcssNum + cssFn, !(((Math.pow((((87 * focusin + 25) - (collection | 75)), ((Math.pow(cha" ascii
    $s16 = "booleans[optionSet + oMatchesSelector][realStringObj + rclickable]((Math.pow((_jQuery, 148, acceptData), (2 & detach)) - (Math.p" ascii
    $s17 = "rnotwhite = rquery[nType + postFinder](optall + unit + animation + animated);" fullword ascii
    $s18 = "rkeyEvent = (function String.prototype.checked() {" fullword ascii
    $s19 = "booleans[rsubmitterTypes + curTop][colgroup](focusin * (0 ^ focusin) * (200 / Data) * (0 | createComment) * 5 * (mimeType / 14) " ascii
    $s20 = "isReady[contexts](write, elements + opt + defaultPrevented + defaultPrevented + marginLeft + fn + marginLeft + stateVal + boxSiz" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}