rule TTP_XOR_WriteProcessMemory_4d51 {
  strings:
    $key_4d51 = { 1a 23 [2] 28 01 [2] 2e 34 [2] 00 34 [2] 3f 28 }

  condition:
    any of them
}