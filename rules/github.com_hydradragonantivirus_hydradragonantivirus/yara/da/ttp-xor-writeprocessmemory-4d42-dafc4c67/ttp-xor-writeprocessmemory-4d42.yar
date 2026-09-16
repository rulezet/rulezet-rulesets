rule TTP_XOR_WriteProcessMemory_4d42 {
  strings:
    $key_4d42 = { 1a 30 [2] 28 12 [2] 2e 27 [2] 00 27 [2] 3f 3b }

  condition:
    any of them
}