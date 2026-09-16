rule TTP_XOR_WriteProcessMemory_6cad {
  strings:
    $key_6cad = { 3b df [2] 09 fd [2] 0f c8 [2] 21 c8 [2] 1e d4 }

  condition:
    any of them
}