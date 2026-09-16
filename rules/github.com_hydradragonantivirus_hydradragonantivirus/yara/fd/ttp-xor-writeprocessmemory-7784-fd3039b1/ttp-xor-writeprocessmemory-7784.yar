rule TTP_XOR_WriteProcessMemory_7784 {
  strings:
    $key_7784 = { 20 f6 [2] 12 d4 [2] 14 e1 [2] 3a e1 [2] 05 fd }

  condition:
    any of them
}