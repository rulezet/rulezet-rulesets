rule TTP_XOR_WriteProcessMemory_e702 {
  strings:
    $key_e702 = { b0 70 [2] 82 52 [2] 84 67 [2] aa 67 [2] 95 7b }

  condition:
    any of them
}