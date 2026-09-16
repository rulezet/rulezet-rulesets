rule sig_20170117_624e34d0e6825e4c256c7dd6e6182af6 {
  meta:
    description = "datamaliciousorder - file 20170117_624e34d0e6825e4c256c7dd6e6182af6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9f9f8f257e8de58e953d5504792c37148a07b4516fc7ea6051ad94bf64add1b"

  strings:
    $s1 = "var wxuhzezhy = new Function(oflowyroskuxyszibsepfutegydyvinyztumry[0] + eramirjugfogcicersizfinuqabrelapretsyzpibdunagjezihsihy" ascii
    $s2 = "var wxuhzezhy = new Function(oflowyroskuxyszibsepfutegydyvinyztumry[0] + eramirjugfogcicersizfinuqabrelapretsyzpibdunagjezihsihy" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}