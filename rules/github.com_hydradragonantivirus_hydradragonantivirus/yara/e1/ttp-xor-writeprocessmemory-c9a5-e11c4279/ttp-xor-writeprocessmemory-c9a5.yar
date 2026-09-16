rule TTP_XOR_WriteProcessMemory_c9a5 {
  strings:
    $key_c9a5 = { 9e d7 [2] ac f5 [2] aa c0 [2] 84 c0 [2] bb dc }

  condition:
    any of them
}