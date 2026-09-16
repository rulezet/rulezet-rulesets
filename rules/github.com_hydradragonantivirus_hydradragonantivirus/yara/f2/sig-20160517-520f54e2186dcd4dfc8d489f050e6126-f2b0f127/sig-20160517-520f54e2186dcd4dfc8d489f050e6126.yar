rule sig_20160517_520f54e2186dcd4dfc8d489f050e6126 {
  meta:
    description = "datamaliciousorder - file 20160517_520f54e2186dcd4dfc8d489f050e6126.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc7d091bf05df1705dcb176c07ed06b3c37594c7c6318a9414e1f504e6cbe6e4"

  strings:
    $s1 = "var ft3='vxhielaa4b1vrkxsjv ebm41zepsbftratl4eark3zkyz4b1sucxqqix3wgbwelvprrzuvygdao2kqsskqaq=p4xot\\'ciwkttahey1cf4vv2njvqdfime" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}