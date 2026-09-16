rule TTP_XOR_WriteProcessMemory_3ed4 {
  strings:
    $key_3ed4 = { 69 a6 [2] 5b 84 [2] 5d b1 [2] 73 b1 [2] 4c ad }

  condition:
    any of them
}