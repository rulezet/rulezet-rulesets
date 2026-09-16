rule TTP_XOR_WriteProcessMemory_1bd1 {
  strings:
    $key_1bd1 = { 4c a3 [2] 7e 81 [2] 78 b4 [2] 56 b4 [2] 69 a8 }

  condition:
    any of them
}