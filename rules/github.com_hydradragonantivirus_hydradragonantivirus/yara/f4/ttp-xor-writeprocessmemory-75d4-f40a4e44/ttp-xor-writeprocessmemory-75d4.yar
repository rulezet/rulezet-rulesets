rule TTP_XOR_WriteProcessMemory_75d4 {
  strings:
    $key_75d4 = { 22 a6 [2] 10 84 [2] 16 b1 [2] 38 b1 [2] 07 ad }

  condition:
    any of them
}