rule TTP_XOR_WriteProcessMemory_4d40 {
  strings:
    $key_4d40 = { 1a 32 [2] 28 10 [2] 2e 25 [2] 00 25 [2] 3f 39 }

  condition:
    any of them
}