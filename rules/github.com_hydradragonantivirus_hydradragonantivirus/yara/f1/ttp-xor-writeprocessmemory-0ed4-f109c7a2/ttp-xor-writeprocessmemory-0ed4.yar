rule TTP_XOR_WriteProcessMemory_0ed4 {
  strings:
    $key_0ed4 = { 59 a6 [2] 6b 84 [2] 6d b1 [2] 43 b1 [2] 7c ad }

  condition:
    any of them
}