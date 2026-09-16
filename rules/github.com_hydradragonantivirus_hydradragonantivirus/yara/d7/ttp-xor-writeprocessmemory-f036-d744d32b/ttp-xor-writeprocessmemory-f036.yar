rule TTP_XOR_WriteProcessMemory_f036 {
  strings:
    $key_f036 = { a7 44 [2] 95 66 [2] 93 53 [2] bd 53 [2] 82 4f }

  condition:
    any of them
}