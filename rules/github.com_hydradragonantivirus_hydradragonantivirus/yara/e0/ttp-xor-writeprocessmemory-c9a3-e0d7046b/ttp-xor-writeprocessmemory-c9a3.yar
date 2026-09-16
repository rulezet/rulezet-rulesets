rule TTP_XOR_WriteProcessMemory_c9a3 {
  strings:
    $key_c9a3 = { 9e d1 [2] ac f3 [2] aa c6 [2] 84 c6 [2] bb da }

  condition:
    any of them
}