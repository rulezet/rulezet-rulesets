rule TTP_XOR_WriteProcessMemory_e4d1 {
  strings:
    $key_e4d1 = { b3 a3 [2] 81 81 [2] 87 b4 [2] a9 b4 [2] 96 a8 }

  condition:
    any of them
}