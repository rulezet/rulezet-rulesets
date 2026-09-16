rule TTP_XOR_WriteProcessMemory_f072 {
  strings:
    $key_f072 = { a7 00 [2] 95 22 [2] 93 17 [2] bd 17 [2] 82 0b }

  condition:
    any of them
}