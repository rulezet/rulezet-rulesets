rule TTP_XOR_WriteProcessMemory_32d4 {
  strings:
    $key_32d4 = { 65 a6 [2] 57 84 [2] 51 b1 [2] 7f b1 [2] 40 ad }

  condition:
    any of them
}