rule _Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_11_Virus_Hijack_445 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_11.vir, Virus.Hijack_Trojan.Agent.DQQO_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac1f5da60126688a9cb3445b984d0971ebbf5af6da2bdcb30ef556fe642763f"
    hash2       = "33a3f8ae4bcda4d513ce8ef0a47d90962f6835b18f5d9ed483e104fd9ef22f25"

  strings:
    $s1 = "<meta http-equiv=*content-type* content=*text/html; charset=UTF-8*>" fullword wide
    $s2 = "D:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
    $s3 = "style=*width: 100%; height: 100%* tabIndex=-1>" fullword wide
    $s4 = "document.write *<div style='position:absolute; left:0px; top:0px; width:0px; height:0px; z-index:28; visibility: hidden'><APPLET" wide
    $s5 = "<body style=*margin: 0* scroll=no>" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}