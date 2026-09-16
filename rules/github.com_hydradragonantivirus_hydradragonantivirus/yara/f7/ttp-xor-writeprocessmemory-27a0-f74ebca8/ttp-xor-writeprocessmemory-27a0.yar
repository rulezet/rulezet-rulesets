rule TTP_XOR_WriteProcessMemory_27a0 {
  strings:
    $key_27a0 = { 70 d2 [2] 42 f0 [2] 44 c5 [2] 6a c5 [2] 55 d9 }

  condition:
    any of them
}