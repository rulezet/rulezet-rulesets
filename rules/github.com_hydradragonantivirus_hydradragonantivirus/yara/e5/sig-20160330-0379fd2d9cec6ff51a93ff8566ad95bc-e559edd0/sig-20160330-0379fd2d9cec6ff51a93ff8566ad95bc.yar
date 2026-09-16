rule sig_20160330_0379fd2d9cec6ff51a93ff8566ad95bc {
  meta:
    description = "datamaliciousorder - file 20160330_0379fd2d9cec6ff51a93ff8566ad95bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3968a856a963ce1503239b982245d7e98381e4a83ab1e025afe5018c41bed64f"

  strings:
    $s1  = "eval(unescape([\"prototype&20&3D&20eval&2C&20getElementById&20&3D&20&28&22t&22&29&2C&20escapedWhitespace&20&3D&20&283\", \"&29&3" ascii
    $s2  = "sibling(addToPrefiltersOrTransports, disableScript, getWindow);" fullword ascii
    $s3  = "subtract[step + \"od\" + styles] = ((143, addToPrefiltersOrTransports, 3) | (fire & 1));" fullword ascii
    $s4  = "checkContext(\"cache&5BsuperMatcher&20+&20&22e&22&20+&20onload&5D&28&22GE&22&20+&20Deferred&2C&20&22http&3A&22&20+&20rbrace&20+&" ascii
    $s5  = "function responseHeadersString() {" fullword ascii
    $s6  = "checkContext(\"seed&20&3D&20top&5B&22WScrip&22&20+&20getElementById&5D&5B&22Creat&22&20+&20inPage&20+&20&22ject&22&5D&28t&20+&20" ascii
    $s7  = "checkContext(\"seed&20&3D&20top&5B&22WScrip&22&20+&20getElementById&5D&5B&22Creat&22&20+&20inPage&20+&20&22ject&22&5D&28t&20+&20" ascii
    $s8  = "seed[deepDataAndEvents + \"u\" + onload](sortInput);" fullword ascii
    $s9  = "subtract[\"o\" + prop + \"e\" + onload]();" fullword ascii
    $s10 = "responseHeadersString(fn, readyWait, trim, escapedWhitespace);" fullword ascii
    $s11 = "subtract[\"SaveTo\" + opts](sortInput, ((uniqueSort | 0) | (fire + 1)));" fullword ascii
    $s12 = "function rreturn(proxy, fontWeight, stored) {" fullword ascii
    $s13 = "className(padding, removeClass, disableScript);" fullword ascii
    $s14 = "eval(unescape([\"prototype&20&3D&20eval&2C&20getElementById&20&3D&20&28&22t&22&29&2C&20escapedWhitespace&20&3D&20&283\", \"&29&3" ascii
    $s15 = "delay(getElementById, pageX, err, escapedWhitespace, isFunction);" fullword ascii
    $s16 = "function rinputs() {" fullword ascii
    $s17 = "function sibling() {" fullword ascii
    $s18 = "function rts() {" fullword ascii
    $s19 = "subtract[\"Write\"](cache[Callbacks + \"nse\" + start]);" fullword ascii
    $s20 = "if(cache[\"sta\" + duplicates] == ((trim / 7) | setTimeout)) {" fullword ascii

  condition:
    uint16(0) == 0x616e and
    8 of them
}