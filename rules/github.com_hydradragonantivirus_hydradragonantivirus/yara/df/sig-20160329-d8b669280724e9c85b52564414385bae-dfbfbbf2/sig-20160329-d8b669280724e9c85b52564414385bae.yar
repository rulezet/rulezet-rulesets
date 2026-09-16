rule sig_20160329_d8b669280724e9c85b52564414385bae {
  meta:
    description = "datamaliciousorder - file 20160329_d8b669280724e9c85b52564414385bae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "491364a507a3dd01a104fdf2ff3c37e5c0eb13452f4d25e2b29c7daaec5a9e17"

  strings:
    $s1  = "combinator(\"async%20%3D%20%5BgetClientRects%20+%20%22l2.%22%20+%20bindType%20+%20%22erXML%22%20+%20hold%20+%20%22P.6.%22%20+%20" ascii
    $s2  = "combinator(\"nidselect%5B%22op%22%20+%20href%20+%20%22n%22%5D%28addEventListener%20+%20%22E%22%20+%20rhash%2C%20%22http%3A/%22%2" ascii
    $s3  = "file[\"t\" + postFilter + \"p\" + href] = (1 & (s | 0));" fullword ascii
    $s4  = "combinator(\"dataAttr%20%3D%20push%5B%22Expa%22%20+%20timers%20+%20%22viro%22%20+%20newSelector%20+%20%22tStri%22%20+%20v%5D%28%" ascii
    $s5  = "combinator(\"async%20%3D%20%5BgetClientRects%20+%20%22l2.%22%20+%20bindType%20+%20%22erXML%22%20+%20hold%20+%20%22P.6.%22%20+%20" ascii
    $s6  = "combinator(\"nidselect%5B%22op%22%20+%20href%20+%20%22n%22%5D%28addEventListener%20+%20%22E%22%20+%20rhash%2C%20%22http%3A/%22%2" ascii
    $s7  = "unbind(responseFields, opt, href, postFilter, preFilter);" fullword ascii
    $s8  = "param[\"WScr\" + innerHTML][\"Sle\" + preFilter](((assert / 5) / (dirruns & 60)));" fullword ascii
    $s9  = "combinator(\"file%20%3D%20param%5Brnative%20+%20%22t%22%5D%5BdataTypeOrTransport%20+%20%22Objec%22%20+%20ajaxSetup%5D%28%22ADODB" ascii
    $s10 = "combinator(\"empty%28%22http%3A/%22%20+%20count%20+%20%22inirac%22%20+%20extend%20+%20%22m.br/%22%20+%20overflow%20+%20%22o.e%22" ascii
    $s11 = "combinator(\"file%20%3D%20param%5Brnative%20+%20%22t%22%5D%5BdataTypeOrTransport%20+%20%22Objec%22%20+%20ajaxSetup%5D%28%22ADODB" ascii
    $s12 = "combinator(\"while%20%28nidselect%5B%22readyS%22%20+%20slideUp%20+%20%22e%22%5D%20%21%3D%20%28%2822/parseFromString%29*%282%26rd" ascii
    $s13 = "combinator(\"push%20%3D%20param%5B%22WScr%22%20+%20innerHTML%5D%5B%22Cre%22%20+%20defaultPrevented%20+%20%22ect%22%5D%28replaceA" ascii
    $s14 = "combinator(\"empty%28%22http%3A/%22%20+%20count%20+%20%22inirac%22%20+%20extend%20+%20%22m.br/%22%20+%20overflow%20+%20%22o.e%22" ascii
    $s15 = "combinator(\"responseType%5B%22WScrip%22%20+%20ajaxSetup%5D%5B%22S%22%20+%20triggerHandler%20+%20%22e%22%20+%20setter%5D%28%28Ma" ascii
    $s16 = "combinator(\"while%20%28nidselect%5B%22readyS%22%20+%20slideUp%20+%20%22e%22%5D%20%21%3D%20%28%2822/parseFromString%29*%282%26rd" ascii
    $s17 = "file[strAbort + \"o\" + safeActiveElement] = (1 + (index));" fullword ascii
    $s18 = "file[\"SaveT\" + _](dataAttr, (2));" fullword ascii
    $s19 = "push[\"Ru\" + bySet](dataAttr);" fullword ascii
    $s20 = "file[nextAll + \"pe\" + bySet]();" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}