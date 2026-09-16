rule TTP_XOR_WriteProcessMemory_4391 {
  strings:
    $key_4391 = { 14 e3 [2] 26 c1 [2] 20 f4 [2] 0e f4 [2] 31 e8 }

  condition:
    any of them
}