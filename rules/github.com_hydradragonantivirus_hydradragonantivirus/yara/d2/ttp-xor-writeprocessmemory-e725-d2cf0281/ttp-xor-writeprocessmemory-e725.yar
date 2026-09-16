rule TTP_XOR_WriteProcessMemory_e725 {
  strings:
    $key_e725 = { b0 57 [2] 82 75 [2] 84 40 [2] aa 40 [2] 95 5c }

  condition:
    any of them
}