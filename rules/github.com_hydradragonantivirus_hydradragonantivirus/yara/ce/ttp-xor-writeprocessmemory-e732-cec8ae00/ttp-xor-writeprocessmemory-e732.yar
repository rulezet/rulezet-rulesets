rule TTP_XOR_WriteProcessMemory_e732 {
  strings:
    $key_e732 = { b0 40 [2] 82 62 [2] 84 57 [2] aa 57 [2] 95 4b }

  condition:
    any of them
}