rule TTP_XOR_WriteProcessMemory_6ca9 {
  strings:
    $key_6ca9 = { 3b db [2] 09 f9 [2] 0f cc [2] 21 cc [2] 1e d0 }

  condition:
    any of them
}