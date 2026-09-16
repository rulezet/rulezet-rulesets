rule TTP_XOR_WriteProcessMemory_e710 {
  strings:
    $key_e710 = { b0 62 [2] 82 40 [2] 84 75 [2] aa 75 [2] 95 69 }

  condition:
    any of them
}