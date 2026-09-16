rule TTP_XOR_WriteProcessMemory_c9a7 {
  strings:
    $key_c9a7 = { 9e d5 [2] ac f7 [2] aa c2 [2] 84 c2 [2] bb de }

  condition:
    any of them
}