rule TTP_XOR_WriteProcessMemory_f073 {
  strings:
    $key_f073 = { a7 01 [2] 95 23 [2] 93 16 [2] bd 16 [2] 82 0a }

  condition:
    any of them
}