rule TTP_XOR_WriteProcessMemory_1380 {
  strings:
    $key_1380 = { 44 f2 [2] 76 d0 [2] 70 e5 [2] 5e e5 [2] 61 f9 }

  condition:
    any of them
}