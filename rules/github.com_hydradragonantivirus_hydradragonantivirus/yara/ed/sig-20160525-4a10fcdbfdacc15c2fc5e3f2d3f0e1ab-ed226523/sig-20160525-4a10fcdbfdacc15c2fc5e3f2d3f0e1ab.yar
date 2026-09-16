rule sig_20160525_4a10fcdbfdacc15c2fc5e3f2d3f0e1ab {
  meta:
    description = "datamaliciousorder - file 20160525_4a10fcdbfdacc15c2fc5e3f2d3f0e1ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30997cdf60d3105619578f7b8518ae28f834cbe2a57b54eae9d6ce235f131b49"

  strings:
    $s1 = "+ sdnetv[eixodb    \\n;)(]gsml[eixodb    \\n         ;mb = ]rerednerp + cthp[eixodb    \\n;tsilslianbmuhtoa = ]dnenoisillocn + s" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}