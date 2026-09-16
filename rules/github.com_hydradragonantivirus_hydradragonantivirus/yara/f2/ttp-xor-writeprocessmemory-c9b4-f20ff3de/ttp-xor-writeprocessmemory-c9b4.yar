rule TTP_XOR_WriteProcessMemory_c9b4 {
  strings:
    $key_c9b4 = { 9e c6 [2] ac e4 [2] aa d1 [2] 84 d1 [2] bb cd }

  condition:
    any of them
}