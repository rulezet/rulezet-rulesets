rule TTP_XOR_WriteProcessMemory_7cad {
  strings:
    $key_7cad = { 2b df [2] 19 fd [2] 1f c8 [2] 31 c8 [2] 0e d4 }

  condition:
    any of them
}