rule TTP_XOR_WriteProcessMemory_f5b1 {
  strings:
    $key_f5b1 = { a2 c3 [2] 90 e1 [2] 96 d4 [2] b8 d4 [2] 87 c8 }

  condition:
    any of them
}