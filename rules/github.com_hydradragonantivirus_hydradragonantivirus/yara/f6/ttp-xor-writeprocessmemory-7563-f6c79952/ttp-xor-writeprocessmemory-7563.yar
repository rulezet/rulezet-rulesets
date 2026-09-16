rule TTP_XOR_WriteProcessMemory_7563 {
  strings:
    $key_7563 = { 22 11 [2] 10 33 [2] 16 06 [2] 38 06 [2] 07 1a }

  condition:
    any of them
}