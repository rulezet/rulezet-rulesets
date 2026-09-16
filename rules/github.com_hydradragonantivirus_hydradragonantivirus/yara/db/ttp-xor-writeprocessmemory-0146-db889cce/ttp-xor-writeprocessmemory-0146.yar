rule TTP_XOR_WriteProcessMemory_0146 {
  strings:
    $key_0146 = { 56 34 [2] 64 16 [2] 62 23 [2] 4c 23 [2] 73 3f }

  condition:
    any of them
}