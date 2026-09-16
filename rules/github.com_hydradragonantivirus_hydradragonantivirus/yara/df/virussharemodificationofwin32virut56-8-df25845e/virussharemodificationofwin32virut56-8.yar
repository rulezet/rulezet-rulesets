rule VirusSharemodificationofWin32Virut56_8 {
  meta:
    description = "datamaliciousorder - file VirusSharemodificationofWin32Virut56_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f718c9f2d9063d7a59549db0fd8359fc1cb9da8ca6ba52cd3ffffcedabe76a7d"

  strings:
    $s1  = "                    <element id=atom(welcomeshadow) content=rcstr(7)/>" fullword ascii
    $s2  = "    logonaccount [selected]" fullword ascii
    $s3  = "    element [id=atom(passwordpanelayer)]" fullword ascii
    $s4  = "    edit [id=atom(password)]" fullword ascii
    $s5  = "        <edit id=atom(password) layoutpos=left width=163rp/>" fullword ascii
    $s6  = "                    <element id=atom(welcome) content=rcstr(7)/>" fullword ascii
    $s7  = "        content: dtb(handlemap(1), 9, 2);" fullword ascii
    $s8  = "                    <element layoutpos=left content=rcbmp(108,3,-1,26rp,26rp,0,0)/>" fullword ascii
    $s9  = "        content: rcbmp(110,3,-1,sysmetric(20),sysmetric(20),0,0);" fullword ascii
    $s10 = "            <element id=atom(instruct) layoutpos=right content=rcstr(25) width=325rp/>" fullword ascii
    $s11 = "                    <element layoutpos=left content=rcbmp(107,3,-1,26rp,26rp,0,0) />" fullword ascii
    $s12 = "    <element id=atom(contentcontainer) layout=flowlayout(1,3,2,3) layoutpos=client content=rcbmp(100,0,0,219rp,207rp,1,0)>" fullword ascii
    $s13 = "    <element id=atom(instruct) layoutpos=bottom content=rcstr(6)/>" fullword ascii
    $s14 = "    element [id=atom(leftpanel)]" fullword ascii
    $s15 = "        content: rcbmp(109,3,-1,sysmetric(20),sysmetric(20),0,0);" fullword ascii
    $s16 = "        animation: alpha | log | fast;" fullword ascii
    $s17 = "        content: rcbmp(105,3,-1,28rp,28rp,0,0);" fullword ascii
    $s18 = "        content: rcbmp(106,3,-1,28rp,28rp,0,0);" fullword ascii
    $s19 = "        content: dtb(handlemap(1), 9, 3);" fullword ascii
    $s20 = "        <element id=atom(leftpanel) sheet=styleref(leftpanelss) layout=filllayout() layoutpos=left>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}