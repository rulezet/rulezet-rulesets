rule sig_20160904_5b130c687eccffba022b15eff0f215fd {
  meta:
    description = "datamaliciousorder - file 20160904_5b130c687eccffba022b15eff0f215fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97d01d06666fe76207d197aedca730d220bd39e48de64666599d89e8a48584df"

  strings:
    $s1 = "   return WScript[NIXZYCMEF+GFCRNQ+XQHEXFKQ+TDUBCUMW+JVZKGZEIC+DSECV+SMRKULJ+KTFZEA+BEJLNQSKR+VCODCDY+NIBRWKM+KZSLD](GMLJHQUAE);" ascii
    $s2 = "   return WScript[NIXZYCMEF+GFCRNQ+XQHEXFKQ+TDUBCUMW+JVZKGZEIC+DSECV+SMRKULJ+KTFZEA+BEJLNQSKR+VCODCDY+NIBRWKM+KZSLD](GMLJHQUAE);" ascii
    $s3 = "//gkps2 h6yl ZNJwX7MJQ8 O5k3zEfoUGJvibp8FvWZ8A6JMTjXRCcN Ig 4 FunD 06bJ2 ls rxYQGXenAcBqiJ4TaN9K dQV wgRQM3vmjWZ Prh1CrPVFPDegmB" ascii
    $s4 = "  return DGTXIEIT; " fullword ascii
    $s5 = "//gkps2 h6yl ZNJwX7MJQ8 O5k3zEfoUGJvibp8FvWZ8A6JMTjXRCcN Ig 4 FunD 06bJ2 ls rxYQGXenAcBqiJ4TaN9K dQV wgRQM3vmjWZ Prh1CrPVFPDegmB" ascii

  condition:
    uint16(0) == 0x2f2f and
    all of them
}