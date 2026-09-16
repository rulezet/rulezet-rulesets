rule TTP_XOR_WriteProcessMemory_55d1 {
  strings:
    $key_55d1 = { 02 a3 [2] 30 81 [2] 36 b4 [2] 18 b4 [2] 27 a8 }

  condition:
    any of them
}