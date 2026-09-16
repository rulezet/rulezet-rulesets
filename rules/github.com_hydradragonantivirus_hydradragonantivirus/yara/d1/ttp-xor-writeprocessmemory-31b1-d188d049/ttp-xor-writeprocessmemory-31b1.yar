rule TTP_XOR_WriteProcessMemory_31b1 {
  strings:
    $key_31b1 = { 66 c3 [2] 54 e1 [2] 52 d4 [2] 7c d4 [2] 43 c8 }

  condition:
    any of them
}