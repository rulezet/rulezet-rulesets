rule TTP_XOR_WriteProcessMemory_1384 {
  strings:
    $key_1384 = { 44 f6 [2] 76 d4 [2] 70 e1 [2] 5e e1 [2] 61 fd }

  condition:
    any of them
}