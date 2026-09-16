rule TTP_XOR_WriteProcessMemory_e796 {
  strings:
    $key_e796 = { b0 e4 [2] 82 c6 [2] 84 f3 [2] aa f3 [2] 95 ef }

  condition:
    any of them
}