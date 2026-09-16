rule TTP_XOR_WriteProcessMemory_f033 {
  strings:
    $key_f033 = { a7 41 [2] 95 63 [2] 93 56 [2] bd 56 [2] 82 4a }

  condition:
    any of them
}