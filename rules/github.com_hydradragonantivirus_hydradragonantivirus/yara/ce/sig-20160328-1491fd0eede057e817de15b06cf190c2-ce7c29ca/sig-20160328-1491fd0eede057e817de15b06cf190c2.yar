rule sig_20160328_1491fd0eede057e817de15b06cf190c2 {
  meta:
    description = "datamaliciousorder - file 20160328_1491fd0eede057e817de15b06cf190c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9300d308131410dc388e378129ecb44c780b938215d5ccf3209d232bc3f9614d"

  strings:
    $x1  = "eval(textContent(\"subordinate%20%3D%20%28%22yState%22%29%3Bvar%20returnValue%20%3D%20%281512%29%2C%20pushStack%20%3D%20%28%22Se" ascii
    $s2  = "    parent(textContent(\"add%28%22http%3A%22%20+%20manipulationTarget%20+%20%22gue%22%20+%20removeAttribute%20+%20%22r/1%22%20+%" ascii
    $s3  = "    parent(textContent(\"add%28%22http%3A%22%20+%20manipulationTarget%20+%20%22gue%22%20+%20removeAttribute%20+%20%22r/1%22%20+%" ascii
    $s4  = "        defaultPrefilter[\"WSc\" + which][\"Sleep\"](((3530 + thead) - (83113 / contentType)));" fullword ascii
    $s5  = "    while (list[\"read\" + subordinate] != (Math.pow((file), 2) - (after + 1))) round[\"WScri\" + ridentifier][\"Sleep\"](((allT" ascii
    $s6  = "    while (list[\"read\" + subordinate] != (Math.pow((file), 2) - (after + 1))) round[\"WScri\" + ridentifier][\"Sleep\"](((allT" ascii
    $s7  = "    parent(textContent(\"list%5B%22op%22%20+%20clearCloneStyle%20+%20%22n%22%5D%28toggleClass%20+%20%22T%22%2C%20test%20+%20%22%" ascii
    $s8  = "    if (list[isEmptyObject + \"us\"] == ((Math.pow(_$, 2) - isLocal) - (1972 / contentType))) {" fullword ascii
    $s9  = "    parent(textContent(\"rscriptTypeMasked%20%3D%20%5BrmultiDash%20+%20%22ml2.%22%20+%20pushStack%20+%20%22rXMLHT%22%20+%20value" ascii
    $s10 = "    parent(textContent(\"list%20%3D%20round%5B%22WScri%22%20+%20ridentifier%5D%5B%22Cre%22%20+%20access%20+%20%22jec%22%20+%20re" ascii
    $s11 = "    parent(textContent(\"requestHeadersNames%20%3D%20sortOrder%5B%22WScri%22%20+%20ridentifier%5D%5B%22Create%22%20+%20namespace" ascii
    $s12 = "    parent(textContent(\"requestHeadersNames%20%3D%20sortOrder%5B%22WScri%22%20+%20ridentifier%5D%5B%22Create%22%20+%20namespace" ascii
    $s13 = "    parent(textContent(\"sortOrder%5Bkey%20+%20%22ript%22%5D%5BmarginLeft%20+%20%22le%22%20+%20swap%5D%28%28%28206%26firing%29%2" ascii
    $s14 = "    parent(textContent(\"rscriptTypeMasked%20%3D%20%5BrmultiDash%20+%20%22ml2.%22%20+%20pushStack%20+%20%22rXMLHT%22%20+%20value" ascii
    $s15 = "function boolHook(responseHeaders) {" fullword ascii
    $s16 = "write%20%3D%20%2837%29%2C%20unqueued%20%3D%20%28%22ironm%22%29%3Bthead%20%3D%20%286359%29%2C%20jsonProp%20%3D%20%28%22ipt.S%22%2" ascii
    $s17 = "    parent(textContent(\"gotoEnd%20%3D%20requestHeadersNames%5BstopQueue%20+%20%22Env%22%20+%20unqueued%20+%20%22entSt%22%20+%20" ascii
    $s18 = "function textContent(originAnchor) {" fullword ascii
    $s19 = "eval(textContent(\"subordinate%20%3D%20%28%22yState%22%29%3Bvar%20returnValue%20%3D%20%281512%29%2C%20pushStack%20%3D%20%28%22Se" ascii
    $s20 = "    parent(textContent(\"gotoEnd%20%3D%20requestHeadersNames%5BstopQueue%20+%20%22Env%22%20+%20unqueued%20+%20%22entSt%22%20+%20" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}