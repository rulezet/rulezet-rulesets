rule TTP_XOR_WriteProcessMemory_47c1 {
  strings:
    $key_47c1 = { 10 b3 [2] 22 91 [2] 24 a4 [2] 0a a4 [2] 35 b8 }

  condition:
    any of them
}