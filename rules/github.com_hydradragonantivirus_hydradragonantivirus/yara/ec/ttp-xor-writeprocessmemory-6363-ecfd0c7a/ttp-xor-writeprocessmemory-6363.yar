rule TTP_XOR_WriteProcessMemory_6363 {
  strings:
    $key_6363 = { 34 11 [2] 06 33 [2] 00 06 [2] 2e 06 [2] 11 1a }

  condition:
    any of them
}