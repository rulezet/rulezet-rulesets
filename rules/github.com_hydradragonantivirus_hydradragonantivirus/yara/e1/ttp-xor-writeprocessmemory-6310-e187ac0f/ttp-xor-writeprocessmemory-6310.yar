rule TTP_XOR_WriteProcessMemory_6310 {
  strings:
    $key_6310 = { 34 62 [2] 06 40 [2] 00 75 [2] 2e 75 [2] 11 69 }

  condition:
    any of them
}