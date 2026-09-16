rule TTP_XOR_WriteProcessMemory_6ba0 {
  strings:
    $key_6ba0 = { 3c d2 [2] 0e f0 [2] 08 c5 [2] 26 c5 [2] 19 d9 }

  condition:
    any of them
}