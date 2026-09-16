rule TTP_XOR_WriteProcessMemory_e751 {
  strings:
    $key_e751 = { b0 23 [2] 82 01 [2] 84 34 [2] aa 34 [2] 95 28 }

  condition:
    any of them
}