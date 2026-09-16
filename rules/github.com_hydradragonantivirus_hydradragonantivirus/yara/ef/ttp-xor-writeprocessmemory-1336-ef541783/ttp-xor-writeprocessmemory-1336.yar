rule TTP_XOR_WriteProcessMemory_1336 {
  strings:
    $key_1336 = { 44 44 [2] 76 66 [2] 70 53 [2] 5e 53 [2] 61 4f }

  condition:
    any of them
}