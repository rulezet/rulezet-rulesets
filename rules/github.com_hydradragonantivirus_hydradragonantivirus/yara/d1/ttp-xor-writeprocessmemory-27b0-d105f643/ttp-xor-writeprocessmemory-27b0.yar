rule TTP_XOR_WriteProcessMemory_27b0 {
  strings:
    $key_27b0 = { 70 c2 [2] 42 e0 [2] 44 d5 [2] 6a d5 [2] 55 c9 }

  condition:
    any of them
}