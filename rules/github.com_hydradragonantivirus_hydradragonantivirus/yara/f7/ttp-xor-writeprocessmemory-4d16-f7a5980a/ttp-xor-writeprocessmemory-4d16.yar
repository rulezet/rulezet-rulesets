rule TTP_XOR_WriteProcessMemory_4d16 {
  strings:
    $key_4d16 = { 1a 64 [2] 28 46 [2] 2e 73 [2] 00 73 [2] 3f 6f }

  condition:
    any of them
}