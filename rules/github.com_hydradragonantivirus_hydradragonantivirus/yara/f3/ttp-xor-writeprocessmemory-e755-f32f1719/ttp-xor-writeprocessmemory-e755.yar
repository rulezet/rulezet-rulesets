rule TTP_XOR_WriteProcessMemory_e755 {
  strings:
    $key_e755 = { b0 27 [2] 82 05 [2] 84 30 [2] aa 30 [2] 95 2c }

  condition:
    any of them
}