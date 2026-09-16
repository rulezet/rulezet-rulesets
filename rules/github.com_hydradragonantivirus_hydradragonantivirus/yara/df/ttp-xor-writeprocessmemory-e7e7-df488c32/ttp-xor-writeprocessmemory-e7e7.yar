rule TTP_XOR_WriteProcessMemory_e7e7 {
  strings:
    $key_e7e7 = { b0 95 [2] 82 b7 [2] 84 82 [2] aa 82 [2] 95 9e }

  condition:
    any of them
}