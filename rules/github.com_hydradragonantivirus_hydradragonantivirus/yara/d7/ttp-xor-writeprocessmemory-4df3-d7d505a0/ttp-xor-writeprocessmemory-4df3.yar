rule TTP_XOR_WriteProcessMemory_4df3 {
  strings:
    $key_4df3 = { 1a 81 [2] 28 a3 [2] 2e 96 [2] 00 96 [2] 3f 8a }

  condition:
    any of them
}