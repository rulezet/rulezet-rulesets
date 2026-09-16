rule sig_20160311_a3e55557fc4496488b099350bee458fd {
  meta:
    description = "datamaliciousorder - file 20160311_a3e55557fc4496488b099350bee458fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "509a7aa6b6a745e0d4d2db3498ee6451d5c846e82f9d1da6ede26cb4cda1c605"

  strings:
    $s1  = "preferredDoc = responseType[ownerDocument + \"andEnv\" + dest + \"ntSt\".focus() + getter](\"%TEMP%\" + max) + \"no\" + rbrace +" ascii
    $s2  = "preferredDoc = responseType[ownerDocument + \"andEnv\" + dest + \"ntSt\".focus() + getter](\"%TEMP%\" + max) + \"no\" + rbrace +" ascii
    $s3  = "radio[\"R\".focus() + rparentsprev](preferredDoc.focus(((urlAnchor - 25) * (rsingleTag + 2) + (getAllResponseHeaders & 30))), ((" ascii
    $s4  = "namespace[getElementsByName + \"File\".focus()](preferredDoc, ((count - 45) * (siblings - 27)));" fullword ascii
    $s5  = "radio[\"R\".focus() + rparentsprev](preferredDoc.focus(((urlAnchor - 25) * (rsingleTag + 2) + (getAllResponseHeaders & 30))), ((" ascii
    $s6  = "innerHTML[\"op\" + childNodes + \"n\".focus()](interval + \"ET\", clazz + \"/www.\" + removeProp + \"stav.c\".focus() + checked " ascii
    $s7  = "responseType = ontype[\"Crea\" + marginLeft + \"bje\" + unit](\"WSc\".focus() + raw + \".Shell\");" fullword ascii
    $s8  = "firing = (((24, cacheURL, 178, sibling) | (24 * results)), (Math.pow((3 * queue), (2 & results)) - (Math.pow(62, results) - 3776" ascii
    $s9  = "firing = (((24, cacheURL, 178, sibling) | (24 * results)), (Math.pow((3 * queue), (2 & results)) - (Math.pow(62, results) - 3776" ascii
    $s10 = "*5%29*%28attributes-4%29*queue*2*%28map%2C148%2ClastModified%29*%285%7CrsingleTag%29*2*%28getAttribute%2C47%2Copener%2C2%29%29%3" ascii
    $s11 = "function postDispatch() {" fullword ascii
    $s12 = "getter = \"rings\";" fullword ascii
    $s13 = "getElementsByName = \"saveTo\", attributes = 9, siblings = 29, queue = 3;" fullword ascii
    $s14 = "namespace = firing[type + \"ript\"][els + \"eObje\" + unit](\"ADOD\".focus() + finalValue + \"ream\");" fullword ascii
    $s15 = "ontype = firing[\"WScr\".focus() + value];" fullword ascii
    $s16 = "innerHTML = firing[\"WScr\" + value][\"Creat\" + rpseudo + \"ct\".focus()](rdashAlpha + \".XMLHT\" + nextSibling);" fullword ascii
    $s17 = "innerHTML[\"op\" + childNodes + \"n\".focus()](interval + \"ET\", clazz + \"/www.\" + removeProp + \"stav.c\".focus() + checked " ascii
    $s18 = "transport = \"wr\";" fullword ascii
    $s19 = "return shift" fullword ascii
    $s20 = "eval(unescape(\"%20%20%20%20%20%20%20%20firing%5B%22WScr%22%20+%20value%5D%5B%22Slee%22%20+%20multipleContexts%5D%28%28rsingleTa" ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}