rule Virus_Autorun_Win32_Neshta_A_16 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d401f2b7b2c6f179da6ea52debbeabc6ae8dbd02e7597659197b32df38ac124"

  strings:
    $s1  = "3856ad364e35_0.0.0.0_zh-tw_e162416486995985 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s2  = "3856ad364e35_0.0.0.0_nb-no_38ac3fc129e29535 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s3  = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s4  = "3856ad364e35_0.0.0.0_pl-pl_7d27e58110310cbe (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s5  = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s6  = "3856ad364e35_0.0.0.0_pt-pt_805d9f910e2a107e (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s7  = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s8  = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s9  = "3856ad364e35_0.0.0.0_ko-kr_5019be8c51bd6979 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s10 = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s11 = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s12 = "3856ad364e35_0.0.0.0_nl-nl_36eb8aff2b0e9f0a (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s13 = "3856ad364e35_0.0.0.0_zh-cn_dd66040e89287d15 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s14 = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-msauditevtlog_31bf3856ad364" ascii
    $s15 = "3856ad364e35_0.0.0.0_tr-tr_0c08e610d8f0aaf6 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s16 = "3856ad364e35_0.0.0.0_he-il_648214257b6eabf8 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii
    $s17 = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s18 = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s19 = "2019-02-21 08:33:07, Info                  CBS    Appl: Selfupdate, Component: x86_microsoft-windows-m..ditevtlog.resources_31bf" ascii
    $s20 = "3856ad364e35_0.0.0.0_pt-br_7f7bd0250ebaa0a2 (6.1.7601.23136), elevation:2, lower version revision holder: 0.0.0.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}