rule TTP_XOR_WriteProcessMemory_f063 {
  strings:
    $key_f063 = { a7 11 [2] 95 33 [2] 93 06 [2] bd 06 [2] 82 1a }

  condition:
    any of them
}