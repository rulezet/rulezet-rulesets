rule TTP_XOR_WriteProcessMemory_e7f5 {
  strings:
    $key_e7f5 = { b0 87 [2] 82 a5 [2] 84 90 [2] aa 90 [2] 95 8c }

  condition:
    any of them
}