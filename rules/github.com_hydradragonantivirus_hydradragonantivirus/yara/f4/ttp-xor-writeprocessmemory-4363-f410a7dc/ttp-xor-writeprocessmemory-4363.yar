rule TTP_XOR_WriteProcessMemory_4363 {
  strings:
    $key_4363 = { 14 11 [2] 26 33 [2] 20 06 [2] 0e 06 [2] 31 1a }

  condition:
    any of them
}