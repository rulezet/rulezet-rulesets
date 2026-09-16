rule TTP_XOR_WriteProcessMemory_ccad {
  strings:
    $key_ccad = { 9b df [2] a9 fd [2] af c8 [2] 81 c8 [2] be d4 }

  condition:
    any of them
}