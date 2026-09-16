rule TTP_XOR_WriteProcessMemory_27b3 {
  strings:
    $key_27b3 = { 70 c1 [2] 42 e3 [2] 44 d6 [2] 6a d6 [2] 55 ca }

  condition:
    any of them
}