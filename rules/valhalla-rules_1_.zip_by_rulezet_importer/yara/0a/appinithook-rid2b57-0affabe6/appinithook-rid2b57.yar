rule AppInitHook_RID2B57 : DEMO EXE FILE HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook_RID2B57.dll"
      author = "Florian Roth"
      reference = "https://github.com/subTee/AppInitGlobalHooks-Mimikatz"
      date = "2015-07-15 09:02:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, EXE, FILE, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Release\\AppInitHook_RID2B57.pdb" ascii
      $s1 = "AppInitHook_RID2B57.dll" fullword ascii
      $s2 = "mimikatz.exe" fullword wide
      $s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
      $s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
      $s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
      $s6 = "VoidFunc" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 4 of them
}