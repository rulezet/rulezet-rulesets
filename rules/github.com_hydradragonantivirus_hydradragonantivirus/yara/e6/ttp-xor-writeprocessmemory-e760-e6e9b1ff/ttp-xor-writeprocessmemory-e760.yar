rule TTP_XOR_WriteProcessMemory_e760 {
  strings:
    $key_e760 = { b0 12 [2] 82 30 [2] 84 05 [2] aa 05 [2] 95 19 }

  condition:
    any of them
}