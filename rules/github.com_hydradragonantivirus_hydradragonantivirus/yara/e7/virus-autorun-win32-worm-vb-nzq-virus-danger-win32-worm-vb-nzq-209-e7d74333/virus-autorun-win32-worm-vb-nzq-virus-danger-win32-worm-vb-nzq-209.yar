rule _Virus_Autorun_Win32_Worm_VB_NZQ_Virus_Danger_Win32_Worm_VB_NZQ__209 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Win32.Worm.VB.NZQ.vir, Virus.Danger_Win32.Worm.VB.NZQ.vir, Virus.Danger_Win32.Worm.VB.NZQ_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3794834fc24f92c9eca6f2f6f8225070de031e869c2da96e57fc52c83f6066f"
    hash2       = "a98af24eb749b1f0e6f17e981cd17a811f23c14594d444c9f36dbb07eedf6606"
    hash3       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"

  strings:
    $s1  = "SCannot export %1: Error writing the file. There may be a disk or file system error./Console Registry Tool for Windows - version" wide
    $s2  = "BInformation in %1 has been successfully entered into the registry.SCannot import %1: Error opening the file. There may be a dis" wide
    $s3  = "  /s         Compare all subkeys and values" fullword wide
    $s4  = "Error:  Too many command-line parameters" fullword wide
    $s5  = "Error:  Too few command-line parameters" fullword wide
    $s6  = "Error:  Invalid command-line parameters" fullword wide
    $s7  = "    FullKey  - in the form of ROOTKEY\\SubKey name" fullword wide
    $s8  = "         SubKey  - The full name of a registry key under the selected ROOTKEY" fullword wide
    $s9  = "Error:  A remote machine was specified, the root key must be HKLM or HKU." fullword wide
    $s10 = "Error:  The root key must be HKLM or HKU for LOAD/UNLOAD." fullword wide
    $s11 = "Error:  The system was unable to find the specified registry key or value" fullword wide
    $s12 = "Error:  Bad operation.  Use /? for help" fullword wide
    $s13 = "REG QUERY KeyName [/v ValueName | /ve] [/s]" fullword wide
    $s14 = "  0 - Succussful, the result compared is identical" fullword wide
    $s15 = "    Machine - Name of remote machine,  omitting defaults to the current machine" fullword wide
    $s16 = "  /v  query for a specific registry key   " fullword wide
    $s17 = "         ValueName  - The name, under the selected Key, to query" fullword wide
    $s18 = "           Machine  Name of remote machine - omitting defaults to the current" fullword wide
    $s19 = "  /v       The value name, under the selected Key, to add" fullword wide
    $s20 = "    Machine  Name of remote machine - omitting defaults to the current machine" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}