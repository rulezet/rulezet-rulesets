rule TTP_XOR_WriteProcessMemory_4784 {
  strings:
    $key_4784 = { 10 f6 [2] 22 d4 [2] 24 e1 [2] 0a e1 [2] 35 fd }

  condition:
    any of them
}