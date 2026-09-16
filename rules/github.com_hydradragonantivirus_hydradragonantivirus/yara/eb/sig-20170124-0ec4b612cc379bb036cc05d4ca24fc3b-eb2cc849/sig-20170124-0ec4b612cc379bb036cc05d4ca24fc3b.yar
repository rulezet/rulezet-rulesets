rule sig_20170124_0ec4b612cc379bb036cc05d4ca24fc3b {
  meta:
    description = "datamaliciousorder - file 20170124_0ec4b612cc379bb036cc05d4ca24fc3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2230242707c291dd4e040e18392291725e1b0ef129004f3285a55a9189be40b6"

  strings:
    $s1 = "//if ([\"edtyr\", \"yqgodni\", \"uzofn\", \"ymqom\", \"futbedy\", \"awane\", \"nifdabc\", \"yzygco\", \"kkuxywko\", \"ulkod\", " ascii
    $s2 = "uwfe\", \"datke\", \"moswuz\", \"yhifem\", \"ygvobfi\", \"pkyt\", \"uscegmifq\", \"lmorykw\", new Function([\"okci\", \"ynavyg\"" ascii
    $s3 = "bhirojxy1 = this[[\"ufgapu\", \"apo\", \"utajquth\", \"glorohku\", \"uxurbo\", \"kroxotv\", \"ebwe\", \"tjebxi\", \"ajpo\", \"pn" ascii
    $s4 = "bhirojxy1 = this[[\"ufgapu\", \"apo\", \"utajquth\", \"glorohku\", \"uxurbo\", \"kroxotv\", \"ebwe\", \"tjebxi\", \"ajpo\", \"pn" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}