rule TTP_XOR_WriteProcessMemory_e767 {
  strings:
    $key_e767 = { b0 15 [2] 82 37 [2] 84 02 [2] aa 02 [2] 95 1e }

  condition:
    any of them
}