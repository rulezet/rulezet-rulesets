rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aSlVvue_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d16c400ee858a5ba28e94e59da041dbd8ef9efaf6f77ec11fa262876556c98"

  strings:
    $s1  = "Process Count - " fullword wide
    $s2  = "This Period mSec - Processor " fullword wide
    $s3  = " Windows NT Executive" fullword wide
    $s4  = " Processor: % User Time " fullword wide
    $s5  = " Processor: % Privileged Time " fullword wide
    $s6  = "Execution Delay " fullword wide
    $s7  = "% Processor Time " fullword wide
    $s8  = " Processor: % DPC Time " fullword wide
    $s9  = " Processor: % Interrupt Time " fullword wide
    $s10 = "Processor Queue Length " fullword wide
    $s11 = "Process performance object " fullword wide
    $s12 = "Processor performance object " fullword wide
    $s13 = "% Total Processor Time " fullword wide
    $s14 = " Process: % Processor Time " fullword wide
    $s15 = " % Total Processor Time" fullword wide
    $s16 = " Processor: Interrupts/sec " fullword wide
    $s17 = " Process\\\\Page File Bytes" fullword wide
    $s18 = " Process\\\\Page File Bytes Peak" fullword wide
    $s19 = "ID Process " fullword wide
    $s20 = " ID Process " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}