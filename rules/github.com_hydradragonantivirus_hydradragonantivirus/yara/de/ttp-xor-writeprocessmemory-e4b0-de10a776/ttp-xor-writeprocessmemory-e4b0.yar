rule TTP_XOR_WriteProcessMemory_e4b0 {
  strings:
    $key_e4b0 = { b3 c2 [2] 81 e0 [2] 87 d5 [2] a9 d5 [2] 96 c9 }

  condition:
    any of them
}