rule TTP_XOR_WriteProcessMemory_f070 {
  strings:
    $key_f070 = { a7 02 [2] 95 20 [2] 93 15 [2] bd 15 [2] 82 09 }

  condition:
    any of them
}