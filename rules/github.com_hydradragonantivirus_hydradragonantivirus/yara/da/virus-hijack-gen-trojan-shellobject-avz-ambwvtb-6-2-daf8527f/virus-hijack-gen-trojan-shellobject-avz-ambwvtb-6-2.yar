rule Virus_Hijack_Gen_Trojan_ShellObject_avZ_amBwvTb_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "851123391df774fd1a86a83d88dc91470deac308405869696dbec4fc4618e64e"

  strings:
    $s1  = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2;)" fullword ascii
    $s2  = "Temperature Probe" fullword ascii
    $s3  = "Management Controller Host Interface" fullword ascii
    $s4  = "value type error: %s to %s" fullword ascii
    $s5  = "assign error: %s to %s" fullword ascii
    $s6  = "Assertion \"%s\" failed in file \"%s\" at line %d" fullword ascii
    $s7  = "Memory Error Information" fullword ascii
    $s8  = "Method [%d] not exist in JsonArray!" fullword ascii
    $s9  = "64-Bit Memory Error Information" fullword ascii
    $s10 = "Boot Integrity Services (BIS) Entry Point" fullword ascii
    $s11 = "System Slots Information" fullword ascii
    $s12 = "Hash://" fullword ascii
    $s13 = "Method [%s] not exist in JsonObject!" fullword ascii
    $s14 = "Invalid argument to Date encode" fullword ascii
    $s15 = "Exception code: $" fullword ascii
    $s16 = "Illegal hexadecimal characters \"" fullword ascii
    $s17 = "Illegal four-hex-digits \"" fullword ascii
    $s18 = "Enclosure Information" fullword ascii
    $s19 = " encode!" fullword ascii
    $s20 = "Single bit ECC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}