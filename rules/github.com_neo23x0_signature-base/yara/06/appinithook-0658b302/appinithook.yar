rule AppInitHook {
   meta:
      description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/Z292v6"
      date = "2015-07-15"
      score = 70
      hash = "e7563e4f2a7e5f04a3486db4cefffba173349911a3c6abd7ae616d3bf08cfd45"
      id = "73713011-3083-5cdf-b59c-f4da67d2d2ab"
   strings:
      $s0 = "\\Release\\AppInitHook.pdb" ascii
      $s1 = "AppInitHook.dll" fullword ascii
      $s2 = "mimikatz.exe" fullword wide
      $s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
      $s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
      $s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
      $s6 = "VoidFunc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}