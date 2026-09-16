rule TTP_XOR_WriteProcessMemory_f0e4 {
  strings:
    $key_f0e4 = { a7 96 [2] 95 b4 [2] 93 81 [2] bd 81 [2] 82 9d }

  condition:
    any of them
}