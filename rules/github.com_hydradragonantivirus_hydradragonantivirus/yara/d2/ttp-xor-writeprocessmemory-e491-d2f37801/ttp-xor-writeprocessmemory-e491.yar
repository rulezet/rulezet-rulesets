rule TTP_XOR_WriteProcessMemory_e491 {
  strings:
    $key_e491 = { b3 e3 [2] 81 c1 [2] 87 f4 [2] a9 f4 [2] 96 e8 }

  condition:
    any of them
}