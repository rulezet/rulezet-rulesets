rule TTP_XOR_WriteProcessMemory_1d94 {
  strings:
    $key_1d94 = { 4a e6 [2] 78 c4 [2] 7e f1 [2] 50 f1 [2] 6f ed }

  condition:
    any of them
}