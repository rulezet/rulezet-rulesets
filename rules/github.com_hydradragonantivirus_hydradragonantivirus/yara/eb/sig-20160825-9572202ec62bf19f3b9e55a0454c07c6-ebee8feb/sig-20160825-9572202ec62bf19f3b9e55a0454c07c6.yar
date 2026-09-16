rule sig_20160825_9572202ec62bf19f3b9e55a0454c07c6 {
  meta:
    description = "datamaliciousorder - file 20160825_9572202ec62bf19f3b9e55a0454c07c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a72a2173d1001cb2d9088abc80483df8c36dc4b7579eab792ece8714000091"

  strings:
    $s1  = "var tjojuplygra3 = new Array(WScript, \"osymef\", \"lnapsudisyt\", \"evejoma\", \"13170\")[0];" fullword ascii
    $s2  = "var qhugfefonh6 = new Array('Clos', \"vecvimylog\");" fullword ascii
    $s3  = "var peqfimxaz = new Array(\"19812\", \"cmd.\", \"16608\", \"zwuxbehvuly\", \"omotybk\");" fullword ascii
    $s4  = "var jlogfyxmakco1 = new Array(\"ynincibupky\", \"uppafjyxva\", 'le');" fullword ascii
    $s5  = "var pugetowe8 = new Array(\"ysfazgucnec\", \"ToFi\", \"18176\");" fullword ascii
    $s6  = "var dtorusog = new Array(\"21967\", \"opexxyhpuro\", \"ixafveqf\", \"GetS\", \"20664\");" fullword ascii
    $s7  = "var ckohkywqabk = new Array('Get', \"21317\", \"21299\", \"ilpudsakvurto\");" fullword ascii
    $s8  = "var nficyzlen = new Array(\"vonadu\", \"ovuftutdy\", 'run', \"19770\", \"yruvgyjosx\");" fullword ascii
    $s9  = "function uscanhob7() {" fullword ascii
    $s10 = "function utulgu1() {" fullword ascii
    $s11 = "var qhuvkuwqi = new Array(\"csorhebodk\", 'si', \"rimbunabkemz\");" fullword ascii
    $s12 = "function ujkunybho3() {" fullword ascii
    $s13 = "var rlutdatq6 = new Array(\"18331\", \"Sc\", \"16527\");" fullword ascii
    $s14 = "var taryhe9 = new Array(\"onregracg\", \"22072\", \"13021\", 745);" fullword ascii
    $s15 = "function nkexutax0() {" fullword ascii
    $s16 = "return bvywkajmem[\"pogilk\"];" fullword ascii
    $s17 = "function ehoro() {" fullword ascii
    $s18 = "function wmubudc2() {" fullword ascii
    $s19 = "var yfnadv7 = new Array(\"in\", \"15613\", \"19568\", \"23515\", \"clilymah\");" fullword ascii
    $s20 = "var apinyb = new Array('alFo', \"lozufcify\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}