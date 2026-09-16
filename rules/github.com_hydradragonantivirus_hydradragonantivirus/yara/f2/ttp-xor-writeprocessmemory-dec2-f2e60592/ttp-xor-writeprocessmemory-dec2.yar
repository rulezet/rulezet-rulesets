rule TTP_XOR_WriteProcessMemory_dec2 {
  strings:
    $key_dec2 = { 89 b0 [2] bb 92 [2] bd a7 [2] 93 a7 [2] ac bb }

  condition:
    any of them
}