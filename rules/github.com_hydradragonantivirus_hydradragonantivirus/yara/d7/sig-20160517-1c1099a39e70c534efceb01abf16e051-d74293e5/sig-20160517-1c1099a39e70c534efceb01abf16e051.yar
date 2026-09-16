rule sig_20160517_1c1099a39e70c534efceb01abf16e051 {
  meta:
    description = "datamaliciousorder - file 20160517_1c1099a39e70c534efceb01abf16e051.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095baa381e6fd3d216e5507251f123454c8468a94f7ba6cfdab2a84120e34f79"

  strings:
    $s1 = "var d3qc3v='vag2jsafceh2rgaxsu yrt1nekm2nasv3213sehjwucbw1kdagqizjhtcb1dlyyuumrtcp1cqkunbr=whnjv\\'zlmektylqblcaxjssneryprighmsm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}