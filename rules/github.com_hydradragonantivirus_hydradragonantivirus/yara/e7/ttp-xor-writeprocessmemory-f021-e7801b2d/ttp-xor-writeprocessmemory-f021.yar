rule TTP_XOR_WriteProcessMemory_f021 {
  strings:
    $key_f021 = { a7 53 [2] 95 71 [2] 93 44 [2] bd 44 [2] 82 58 }

  condition:
    any of them
}