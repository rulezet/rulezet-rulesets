rule TTP_XOR_WriteProcessMemory_e791 {
  strings:
    $key_e791 = { b0 e3 [2] 82 c1 [2] 84 f4 [2] aa f4 [2] 95 e8 }

  condition:
    any of them
}