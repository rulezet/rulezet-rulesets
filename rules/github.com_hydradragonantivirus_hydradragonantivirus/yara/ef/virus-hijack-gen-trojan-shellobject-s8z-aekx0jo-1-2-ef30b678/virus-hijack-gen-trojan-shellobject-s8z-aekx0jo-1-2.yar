rule Virus_Hijack_Gen_Trojan_ShellObject_S8Z_aeKx0jo_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.S8Z@aeKx0jo_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6f6f11531ceec7cfbe9e8b7696bcbbb989bdc1801769485a68e33c94031c94"

  strings:
    $s1 = "<description>MSN Messenger Service</description>" fullword ascii
    $s2 = "$VMware Tools Service is not running." fullword wide
    $s3 = "This version of VMware Tools is incompatible with VMware." fullword wide
    $s4 = "Enable Drag and Drop" fullword wide
    $s5 = "Copyright (C) 1998-2009 VMware, Inc." fullword wide
    $s6 = "VMware Tools Tray" fullword wide
    $s7 = "Open VMware Tools" fullword wide
    $s8 = "For information on updating your VMware Tools please see" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}