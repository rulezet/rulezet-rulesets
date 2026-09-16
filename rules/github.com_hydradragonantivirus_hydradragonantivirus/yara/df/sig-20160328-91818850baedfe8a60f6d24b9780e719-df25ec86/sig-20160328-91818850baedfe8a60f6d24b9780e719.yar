rule sig_20160328_91818850baedfe8a60f6d24b9780e719 {
  meta:
    description = "datamaliciousorder - file 20160328_91818850baedfe8a60f6d24b9780e719.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acb922dd0c9b65209b2a6069411dd4748ae3651049270efd6c4fb39e03f30a4b"

  strings:
    $x1  = "eval(rquery(\"response%20%3D%20%28%22XML%22%29%2C%20results%20%3D%20%28%22WScr%22%29%3Bidentifier%20%3D%20%28%22r%22%29%2C%20par" ascii
    $x2  = "while (animated[\"ready\" + transport] != ((Math.pow(prefilterOrFactory, 2) - checkClone) / (5 * hasScripts * 5))) manipulationT" ascii
    $s3  = "manipulationTarget[\"WScrip\" + etag][\"Sle\" + calculatePosition + \"p\"](((Math.pow(content, 2) - _) | (4488 | clazz)));" fullword ascii
    $s4  = "while (animated[\"ready\" + transport] != ((Math.pow(prefilterOrFactory, 2) - checkClone) / (5 * hasScripts * 5))) manipulationT" ascii
    $s5  = "textContent(rquery(\"value%20%3D%20isSimulated%5Bpipe%20+%20%22andEnv%22%20+%20rcssNum%20+%20%22nmentS%22%20+%20random%20+%20%22" ascii
    $s6  = "get[\"WScr\" + pseudo][\"Sl\" + promise](((onabort | 169), (xhr - 65), (propHooks | 121), (responseHeadersString, 100)));" fullword ascii
    $s7  = "function disableScript(sortStable, postDispatch, msg) {" fullword ascii
    $s8  = "textContent(rquery(\"high%20%3D%20%5B%22Msxm%22%20+%20filter%20+%20%22erver%22%20+%20response%20+%20%22HTTP%22%20+%20dispatch%2C" ascii
    $s9  = "textContent(rquery(\"value%20%3D%20isSimulated%5Bpipe%20+%20%22andEnv%22%20+%20rcssNum%20+%20%22nmentS%22%20+%20random%20+%20%22" ascii
    $s10 = "textContent(rquery(\"resolve%5B%22mo%22%20+%20createHTMLDocument%20+%20%22e%22%5D%20%3D%20%28%281*getById%29%26%281*getById%29%2" ascii
    $s11 = "textContent(rquery(\"resolve%5B%22mo%22%20+%20createHTMLDocument%20+%20%22e%22%5D%20%3D%20%28%281*getById%29%26%281*getById%29%2" ascii
    $s12 = "resolve[etag + \"yp\" + calculatePosition] = (181, relatedTarget, 1);" fullword ascii
    $s13 = "manipulationTarget = result = siblings = Symbol = mouseHooks._evalUrl();" fullword ascii
    $s14 = "letterSpacing(completeDeferred, random, isXML, hasScripts);" fullword ascii
    $s15 = "textContent(rquery(\"high%20%3D%20%5B%22Msxm%22%20+%20filter%20+%20%22erver%22%20+%20response%20+%20%22HTTP%22%20+%20dispatch%2C" ascii
    $s16 = "for (eq = ((progressContexts - 34) * resolveWith); eq < high[\"l\" + argument + \"th\"]; eq++) {" fullword ascii
    $s17 = "textContent(rquery(\"animated%20%3D%20Symbol%5Bresults%20+%20%22ipt%22%5D%5BmsMatchesSelector%20+%20%22teOb%22%20+%20isXML%20+%2" ascii
    $s18 = "textContent(rquery(\"animated%20%3D%20Symbol%5Bresults%20+%20%22ipt%22%5D%5BmsMatchesSelector%20+%20%22teOb%22%20+%20isXML%20+%2" ascii
    $s19 = "stopOnFalse(textContent, random, filter);" fullword ascii
    $s20 = "resolve[preDispatch + \"ToF\" + getClass](value, ((94, fireWith, 44, namespace) + 1));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}