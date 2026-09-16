rule sig_20160330_caa0c78527260e6dffc0aca265a57fda {
  meta:
    description = "datamaliciousorder - file 20160330_caa0c78527260e6dffc0aca265a57fda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd321bfb3f93f57f1d24cfb73d35b9e41a3b40476b4ddb0c2b40adaf4ff359c0"

  strings:
    $x1  = "eval(unescape([\"var&20marginRight&20&3D&20&28&22dyStat&22&29&3Bvar&20hasContent&20&3D&20&2887&29&3Bvar&20offset&20&3\", \"D&20&" ascii
    $s2  = "getWidthOrHeight = disabled = diff = elemData = password.collection();" fullword ascii
    $s3  = "clientY[htmlPrefilter + \"od\" + temp] = (2 + (_data | 1));" fullword ascii
    $s4  = "   if(parentOffset[combinator + \"tatus\"] == ((attrHandle * 113) - (getAttribute & 191))) {" fullword ascii
    $s5  = "compile&20&3D&20&2810452&29&2C&20text&20&3D&\", \"20&28&22leng&22&29&3Bvar&20getAttribute&20&3D&20&28203&29&2C&20rcomma&20&3D&20" ascii
    $s6  = "         parentOffset[combinator + \"en\" + rheader]();" fullword ascii
    $s7  = "   until(\"indirect&20&3D&20&5BiNoClone&20+&20&222.Serv&22&20+&20getAttributeNode&20+&20&22TTP.6&22&20+&20td&2C&20&22Msxml2&22&2" ascii
    $s8  = "         parentOffset = getWidthOrHeight[mimeType + \"t\"][rsingleTag + \"eObj\" + slideDown](indirect[name]);" fullword ascii
    $s9  = "clientY[\"ty\" + onlyHandlers + \"e\"] = (pseudo, 12, _data);" fullword ascii
    $s10 = "   until(\"while&20&28parentOffset&5B&22rea&22&20+&20marginRight&20+&20&22e&22&5D&20&21&3D&20&28Math.pow&28&2845-getClientRects&" ascii
    $s11 = "22ll&22&29&3B&20last\", \"Child&20&3D&20&28&22t&22&29&3B&20flag&20&3D&20&28&22ADODB.&22&29&3B&20once&20&3D&20&28&22.XML&22&29&\"" ascii
    $s12 = "   until(\"evt&28rxhtmlTag&20+&20&22p&3A//e&22&20+&20last&20+&20&22sa.co&22&20+&20dataTypeOrTransport&20+&20&22NpH&22&20+&20rnoC" ascii
    $s13 = "   until(\"indirect&20&3D&20&5BiNoClone&20+&20&222.Serv&22&20+&20getAttributeNode&20+&20&22TTP.6&22&20+&20td&2C&20&22Msxml2&22&2" ascii
    $s14 = "   until(\"while&20&28parentOffset&5B&22rea&22&20+&20marginRight&20+&20&22e&22&5D&20&21&3D&20&28Math.pow&28&2845-getClientRects&" ascii
    $s15 = "   until(\"attrId&20&3D&20attr&5B&22Expa&22&20+&20isImmediatePropagationStopped&20+&20&22vir&22&20+&20specialEasing&20+&20&22tSt" ascii
    $s16 = "   until(\"clientY&20&3D&20disabled&5B&22WSc&22&20+&20rscriptTypeMasked&5D&5B&22Create&22&20+&20originalProperties&20+&20&22t&22" ascii
    $s17 = "   until(\"clientY&20&3D&20disabled&5B&22WSc&22&20+&20rscriptTypeMasked&5D&5B&22Create&22&20+&20originalProperties&20+&20&22t&22" ascii
    $s18 = "      focus(stateString, rscriptTypeMasked, offsetWidth);" fullword ascii
    $s19 = "function evt() {" fullword ascii
    $s20 = "function writable() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}