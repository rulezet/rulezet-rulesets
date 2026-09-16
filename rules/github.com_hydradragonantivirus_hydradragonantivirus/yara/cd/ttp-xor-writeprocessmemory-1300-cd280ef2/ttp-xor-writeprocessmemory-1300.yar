rule TTP_XOR_WriteProcessMemory_1300 {
  strings:
    $key_1300 = { 44 72 [2] 76 50 [2] 70 65 [2] 5e 65 [2] 61 79 }

  condition:
    any of them
}