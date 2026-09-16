rule sig_20160329_ba7b913dff0d37862911f07021836243 {
  meta:
    description = "datamaliciousorder - file 20160329_ba7b913dff0d37862911f07021836243.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d2fcc2c1844f7bcc5603f64fd1f7e4fb02f713fc94c7afed1296a64ffc8714a"

  strings:
    $s1  = "stop[class2type + \"oFile\"](rkeyEvent, ((Math.pow(text, 2) - matched) / (4 + getJSON)));" fullword ascii
    $s2  = "replaceAll(\"padding%5BmarkFunction%20+%20%22e%22%20+%20dataUser%5D%28%22GE%22%20+%20defaultExtra%2C%20%22http%3A/%22%20+%20curr" ascii
    $s3  = "getAllResponseHeaders[rfocusable + \"pt\"][serialize + \"p\"](((fx | 32920) / (tuple - 5)));" fullword ascii
    $s4  = "wrap[eventDoc + \"n\"](rkeyEvent);" fullword ascii
    $s5  = "replaceAll(\"tmp%5BcreatePositionalPseudo%20+%20%22ript%22%5D%5BgetComputedStyle%20+%20%22ep%22%5D%28%28%285*name*5*origCount*2*" ascii
    $s6  = "nt%20+%20%22par%22%20+%20clientTop%20+%20%22com/%22%20+%20hidden%20+%20%22.exe%22%2C%20%21%28finalValue%20%3D%3D%20%28%282*name*" ascii
    $s7  = "if(padding[\"sta\" + th] == ((restoreScript / 49))) {" fullword ascii
    $s8  = "function doc(target) {" fullword ascii
    $s9  = "padding = buildParams[\"WScrip\" + isSimulated][\"Create\" + pageYOffset + \"t\"](bubbleType[getElementsByName]);" fullword ascii
    $s10 = "replaceAll(\"while%20%28padding%5B%22rea%22%20+%20propFix%20+%20%22te%22%5D%20%21%3D%20%28%282+name%29%7C0%29%29%20getAllRespons" ascii
    $s11 = "replaceAll(\"tmp%5BcreatePositionalPseudo%20+%20%22ript%22%5D%5BgetComputedStyle%20+%20%22ep%22%5D%28%28%285*name*5*origCount*2*" ascii
    $s12 = "stop[\"o\" + unquoted + \"e\" + dataUser]();" fullword ascii
    $s13 = "padding[ajaxTransport + \"n\" + find]();" fullword ascii
    $s14 = "overwritten(eased, uniqueSort, hide, uniqueSort, restoreScript);" fullword ascii
    $s15 = "replaceAll(\"padding%5BmarkFunction%20+%20%22e%22%20+%20dataUser%5D%28%22GE%22%20+%20defaultExtra%2C%20%22http%3A/%22%20+%20curr" ascii
    $s16 = "replaceAll(\"wrap%20%3D%20_data%5B%22WScri%22%20+%20isBorderBox%5D%5B%22Cre%22%20+%20requestHeaders%20+%20%22ect%22%5D%28rfocusa" ascii
    $s17 = "replaceAll(\"stop%20%3D%20getAllResponseHeaders%5B%22WScrip%22%20+%20isSimulated%5D%5B%22Creat%22%20+%20children%20+%20%22ct%22%" ascii
    $s18 = "replaceAll(\"while%20%28padding%5B%22rea%22%20+%20propFix%20+%20%22te%22%5D%20%21%3D%20%28%282+name%29%7C0%29%29%20getAllRespons" ascii
    $s19 = "replaceAll(\"wrap%20%3D%20_data%5B%22WScri%22%20+%20isBorderBox%5D%5B%22Cre%22%20+%20requestHeaders%20+%20%22ect%22%5D%28rfocusa" ascii
    $s20 = "replaceAll(\"stop%20%3D%20getAllResponseHeaders%5B%22WScrip%22%20+%20isSimulated%5D%5B%22Creat%22%20+%20children%20+%20%22ct%22%" ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}