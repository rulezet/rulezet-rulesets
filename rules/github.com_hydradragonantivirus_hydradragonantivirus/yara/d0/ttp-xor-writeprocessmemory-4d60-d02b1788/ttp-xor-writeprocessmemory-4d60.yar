rule TTP_XOR_WriteProcessMemory_4d60 {
  strings:
    $key_4d60 = { 1a 12 [2] 28 30 [2] 2e 05 [2] 00 05 [2] 3f 19 }

  condition:
    any of them
}