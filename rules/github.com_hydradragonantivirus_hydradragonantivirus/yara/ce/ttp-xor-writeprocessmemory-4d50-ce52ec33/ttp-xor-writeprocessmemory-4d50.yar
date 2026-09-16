rule TTP_XOR_WriteProcessMemory_4d50 {
  strings:
    $key_4d50 = { 1a 22 [2] 28 00 [2] 2e 35 [2] 00 35 [2] 3f 29 }

  condition:
    any of them
}