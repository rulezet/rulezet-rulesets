rule TTP_XOR_WriteProcessMemory_64d4 {
  strings:
    $key_64d4 = { 33 a6 [2] 01 84 [2] 07 b1 [2] 29 b1 [2] 16 ad }

  condition:
    any of them
}