rule TTP_XOR_WriteProcessMemory_4472 {
  strings:
    $key_4472 = { 13 00 [2] 21 22 [2] 27 17 [2] 09 17 [2] 36 0b }

  condition:
    any of them
}