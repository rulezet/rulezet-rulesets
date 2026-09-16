rule TTP_XOR_WriteProcessMemory_f372 {
  strings:
    $key_f372 = { a4 00 [2] 96 22 [2] 90 17 [2] be 17 [2] 81 0b }

  condition:
    any of them
}