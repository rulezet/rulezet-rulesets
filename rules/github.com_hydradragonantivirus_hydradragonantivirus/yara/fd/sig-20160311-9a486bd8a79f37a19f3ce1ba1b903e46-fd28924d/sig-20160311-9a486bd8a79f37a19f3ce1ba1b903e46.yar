rule sig_20160311_9a486bd8a79f37a19f3ce1ba1b903e46 {
  meta:
    description = "datamaliciousorder - file 20160311_9a486bd8a79f37a19f3ce1ba1b903e46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a558c1c40a58facb7a1105258735f4af4f10653c4faf254972268dd6341b8ea4"

  strings:
    $s1  = "push = ((Math.pow((324 & isReady), 2) - notify * 127 * exports), (3 & clientTop), eval(\"t\" + setTimeout + \"is\".completeDefer" ascii
    $s2  = "push = ((Math.pow((324 & isReady), 2) - notify * 127 * exports), (3 & clientTop), eval(\"t\" + setTimeout + \"is\".completeDefer" ascii
    $s3  = "getElementsByName[transport + \"u\".completeDeferred() + parseOnly](sortInput.completeDeferred(((15 & preFilters) + (75 & bup)))" ascii
    $s4  = "async [destElements + \"en\"](bool + \"E\".completeDeferred() + selection, \"http\" + conv2 + \"fumy\" + idx + \".repub\".comple" ascii
    $s5  = "getElementsByName[transport + \"u\".completeDeferred() + parseOnly](sortInput.completeDeferred(((15 & preFilters) + (75 & bup)))" ascii
    $s6  = "async [destElements + \"en\"](bool + \"E\".completeDeferred() + selection, \"http\" + conv2 + \"fumy\" + idx + \".repub\".comple" ascii
    $s7  = ", (43 - genFx)) - (1 | rejectWith))) & ((Math.pow((19 & prefix), (5 - clientTop)) - 331) & (exports * 5 * clientTop + (1 + xml))" ascii
    $s8  = "async = push[all + \"pt\"][prevAll + \"teOb\" + method](\"MSXML2\".completeDeferred() + sel + \"LHTTP\");" fullword ascii
    $s9  = "pointerenter[\"save\" + clone + \"e\"](sortInput, ((resolve - 22) | exports));" fullword ascii
    $s10 = "pointerenter = push[all + \"pt\"][triggerHandler + \"Objec\" + ajaxSetup](\"ADOD\".completeDeferred() + dataTypeExpression + \"t" ascii
    $s11 = "sconnectedMatch) + (64 | memory)))) / (((2 | exports) * (1 * exports) * (38 / rejectWith) * 3 + (Math.pow((exports * 2 + optall)" ascii
    $s12 = "bup = (function String.prototype.completeDeferred() {" fullword ascii
    $s13 = "funescape = hold[flag + \"eOb\" + cssText + \"t\".completeDeferred()](compare + \"t.Shel\" + rbuggyQSA);" fullword ascii
    $s14 = "hold = push[related + \"ript\"];" fullword ascii
    $s15 = "compare = \"WScrip\"," fullword ascii
    $s16 = "transport = \"R\";" fullword ascii
    $s17 = "method = \"ject\";" fullword ascii
    $s18 = "function defaultPrevented() {" fullword ascii
    $s19 = "notify = 257;" fullword ascii
    $s20 = "return rcssNum" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}