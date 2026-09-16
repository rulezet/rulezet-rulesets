rule TTP_XOR_WriteProcessMemory_4d00 {
  strings:
    $key_4d00 = { 1a 72 [2] 28 50 [2] 2e 65 [2] 00 65 [2] 3f 79 }

  condition:
    any of them
}