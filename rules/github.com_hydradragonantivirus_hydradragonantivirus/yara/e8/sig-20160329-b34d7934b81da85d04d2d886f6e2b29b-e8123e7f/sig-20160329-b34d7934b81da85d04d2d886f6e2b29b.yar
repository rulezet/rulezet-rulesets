rule sig_20160329_b34d7934b81da85d04d2d886f6e2b29b {
  meta:
    description = "datamaliciousorder - file 20160329_b34d7934b81da85d04d2d886f6e2b29b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adcaf3e28e5a346e4947227ac260bc4c48e4a8165e26f718e92f446c1a9f9e13"

  strings:
    $s1  = "marginLeft = headers[\"WScrip\" + operator][\"Cre\" + method + \"Object\"](eventPath[parents]);" fullword ascii
    $s2  = "for(parents = ((Math.pow(top, 2) - root), (241 & originalSettings), (6464 / elementMatchers), (1 + -isEmptyObject)); parents < e" ascii
    $s3  = "headers[\"WScr\" + tweeners][\"Sleep\"](((7899 & jQuery) - (2874 + until)));" fullword ascii
    $s4  = "swing(\"matches%20%3D%20headers%5B%22WScrip%22%20+%20operator%5D%5B%22Creat%22%20+%20etag%20+%20%22t%22%5D%28contexts%20+%20%22i" ascii
    $s5  = "for(parents = ((Math.pow(top, 2) - root), (241 & originalSettings), (6464 / elementMatchers), (1 + -isEmptyObject)); parents < e" ascii
    $s6  = "swing(\"while%20%28marginLeft%5BisPropagationStopped%20+%20%22dySt%22%20+%20method%5D%20%21%3D%20%28%28Math.pow%2828%2C%20getCla" ascii
    $s7  = "swing(\"innerText%20%3D%20matches%5B%22Expan%22%20+%20attrHooks%20+%20%22vironm%22%20+%20removeEventListener%20+%20%22ing%22%20+" ascii
    $s8  = "swing(\"matches%20%3D%20headers%5B%22WScrip%22%20+%20operator%5D%5B%22Creat%22%20+%20etag%20+%20%22t%22%5D%28contexts%20+%20%22i" ascii
    $s9  = "swing(\"eventPath%20%3D%20%5B%22Msx%22%20+%20cur%20+%20%22rverXM%22%20+%20clientTop%20+%20%226.0%22%2C%20cssNumber%20+%20%22l2.%" ascii
    $s10 = "function props(selectedIndex, currentTarget, specialEasing) {" fullword ascii
    $s11 = "swing(\"params%28getStyles%20+%20%22/soci%22%20+%20getElementsByTagName%20+%20%22ildu%22%20+%20addToPrefiltersOrTransports%20+%2" ascii
    $s12 = "swing(\"while%20%28marginLeft%5BisPropagationStopped%20+%20%22dySt%22%20+%20method%5D%20%21%3D%20%28%28Math.pow%2828%2C%20getCla" ascii
    $s13 = "swing(\"params%28getStyles%20+%20%22/soci%22%20+%20getElementsByTagName%20+%20%22ildu%22%20+%20addToPrefiltersOrTransports%20+%2" ascii
    $s14 = "function inArray(triggered, fn, restoreScript) {" fullword ascii
    $s15 = "swing(\"headers%5Bcontexts%20+%20%22ipt%22%5D%5BadjustCSS%20+%20%22e%22%20+%20serialize%5D%28%28%28option/36%29+%28conditionFn%2" ascii
    $s16 = "swing(\"headers%5Bcontexts%20+%20%22ipt%22%5D%5BadjustCSS%20+%20%22e%22%20+%20serialize%5D%28%28%28option/36%29+%28conditionFn%2" ascii
    $s17 = "rwhitespace[\"t\" + finish + \"e\"] = ((isEmptyObject + 0) | (isEmptyObject / 1));" fullword ascii
    $s18 = "rwhitespace[implementation + \"d\" + childNodes] = (3 | (isArrayLike | 0));" fullword ascii
    $s19 = "rwhitespace[parseOnly + \"rite\"](marginLeft[simple + \"nseBod\" + deep]);" fullword ascii
    $s20 = "function fired(index, rootjQuery) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}