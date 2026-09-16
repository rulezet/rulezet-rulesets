rule sig_20150915_f73e3d51b81d20c55edf88dd92f0f0a2 {
  meta:
    description = "datamaliciousorder - file 20150915_f73e3d51b81d20c55edf88dd92f0f0a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ec373f46db9bab9eaab1b60d72bea1caa657a10bd43385b079453805d032f85"

  strings:
    $s1  = "var str=\"5550575E0508010724011C1405101001070C4A070B09\";/* var wdeg=lwiw935394(); */ function lwiw274560() { return '+\"&id'; }" ascii
    $s2  = " lwiw258720() { return 'GET\"'; }; function lwiw118800() { return 'ew '; }; function lwiw211200() { return '000'; }; /* var wdeg" ascii
    $s3  = "* var wdeg=lwiw286519(); */ /* var wdeg=lwiw957270(); */ /* var wdeg=lwiw189967(); */ function lwiw180840() { return 'eam'; }; /" ascii
    $s4  = "* var wdeg=lwiw909836(); */ /* var wdeg=lwiw378757(); */ /* var wdeg=lwiw495136(); */ /* var wdeg=lwiw543454(); */ function lwiw" ascii
    $s5  = "* var wdeg=lwiw926998(); */ /* var wdeg=lwiw348755(); */ /* var wdeg=lwiw433043(); */ function lwiw47520() { return ' { v'; }; /" ascii
    $s6  = "* var wdeg=lwiw765818(); */ function lwiw73920() { return 'ntStr'; }; /* var wdeg=lwiw288587(); */ /* var wdeg=lwiw244734(); */ " ascii
    $s7  = "* var wdeg=lwiw847712(); */ function lwiw155760() { return '4 '; }; /* var wdeg=lwiw239418(); */ function lwiw285120() { return " ascii
    $s8  = "m'; }; function lwiw216480() { return '1; '; }; function lwiw282480() { return 'o.sen'; }; /* var wdeg=lwiw138124(); */ function" ascii
    $s9  = "ction lwiw99000() { return 'an'; }; function lwiw250800() { return ' }; }'; }; function lwiw15840() { return 'com'; }; /* var wd" ascii
    $s10 = "wiw943091(); */ var wdeg = ''; function lwiw234960() { return 's.Run'; }; function lwiw104280() { return '000)+'; }; function lw" ascii
    $s11 = "1388(); */ function lwiw102960() { return '0000'; }; /* var wdeg=lwiw187559(); */ /* var wdeg=lwiw801774(); */ /* var wdeg=lwiw1" ascii
    $s12 = "w21120() { return 'stl'; }; /* var wdeg=lwiw887597(); */ /* var wdeg=lwiw595180(); */ /* var wdeg=lwiw479286(); */ function lwiw" ascii
    $s13 = "ar wdeg=lwiw672033(); */ /* var wdeg=lwiw657791(); */ function lwiw199320() { return 'Resp'; }; /* var wdeg=lwiw787055(); */ /* " ascii
    $s14 = " return '01); '; }; /* var wdeg=lwiw350492(); */ function lwiw114840() { return 'r xo'; }; function lwiw137280() { return 'hang'" ascii
    $s15 = "on lwiw275880() { return '=\"+s'; }; /* var wdeg=lwiw734614(); */ /* var wdeg=lwiw581664(); */ function lwiw257400() { return 'p" ascii
    $s16 = "turn '2)+'; }; /* var wdeg=lwiw450876(); */ /* var wdeg=lwiw629723(); */ function lwiw252120() { return '; tr'; }; /* var wdeg=l" ascii
    $s17 = "function lwiw80520() { return '+Stri'; }; /* var wdeg=lwiw960294(); */ /* var wdeg=lwiw829848(); */ function lwiw245520() { retu" ascii
    $s18 = "tion lwiw147840() { return 'f ('; }; function lwiw109560() { return 'ar '; }; function lwiw42240() { return 'i<b'; }; /* var wde" ascii
    $s19 = "wiw121440() { return 'eXO'; }; function lwiw162360() { return ' =='; }; /* var wdeg=lwiw782786(); */ function lwiw66000() { retu" ascii
    $s20 = " function lwiw167640() { return 'r xa'; }; function lwiw174240() { return 'bje'; }; /* var wdeg=lwiw867896(); */ /* var wdeg=lwi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}