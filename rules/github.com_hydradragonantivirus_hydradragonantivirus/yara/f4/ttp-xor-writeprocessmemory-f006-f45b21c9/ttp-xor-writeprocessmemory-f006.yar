rule TTP_XOR_WriteProcessMemory_f006 {
  strings:
    $key_f006 = { a7 74 [2] 95 56 [2] 93 63 [2] bd 63 [2] 82 7f }

  condition:
    any of them
}