rule _Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_4_2_Virus_Hijac_128 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_239_1.vir, Virus.Hooker_Trojan.GenericKD.72461089_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07a4111d358e8cddb418a922731ac19176f72aeb437b9f71de41fa73b61a9d7f"
    hash2       = "866f9094d79a7b3d100dc3e109caae790ebc934f49d8c1f121cc598799096ecb"
    hash3       = "e68a69947d4508c9c50322964c164c6bb9acf9ec50e9515d684fcb9616fae667"

  strings:
    $s1  = "Description$-{0} Usage Scenarios - this message." fullword ascii
    $s2  = "DescriptionA-{0} Quiet operation - Can only be specified with -version:value." fullword ascii
    $s3  = "DescriptionJ-{0} <options>: all of these options will be passed through to the processT" fullword ascii
    $s4  = "Description -{0} <dll name>: Reference a dllT" fullword ascii
    $s5  = "BriefUsage$example -o <outfile> <other options>T" fullword ascii
    $s6  = "Description.-{0} <user name>: The user name to connect as.T" fullword ascii
    $s7  = "Description5-{0}: if specified a trusted connection will be used." fullword ascii
    $s8  = "Description%-{0} Show currently selected version." fullword ascii
    $s9  = "DescriptionF-{0}[:value] Set WinSDK version. If no version is specified, show all.D" fullword ascii
    $s10 = "Configuration commandT" fullword ascii
    $s11 = "An example commandT" fullword ascii
    $s12 = "            <ComponentShortName>Microsoft .NET Compact Framework 2.0</ComponentShortName>" fullword ascii
    $s13 = "            <ComponentShortName>Microsoft .NET Compact Framework 3.5</ComponentShortName>" fullword ascii
    $s14 = "            <ComponentName>Microsoft .NET Compact Framework 2.0</ComponentName>" fullword ascii
    $s15 = "It's always a good idea to add a general description" fullword ascii
    $s16 = "            <ComponentName>Microsoft .NET Compact Framework 3.5</ComponentName>" fullword ascii
    $s17 = "Description+-{0} <outfile> : Write all output to a filew" fullword ascii
    $s18 = "Windows SDK Configuration Tool" fullword wide
    $s19 = "            nice on the command line.T" fullword ascii
    $s20 = "            of what the command does in the command attribute.  You don't need to worry" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}