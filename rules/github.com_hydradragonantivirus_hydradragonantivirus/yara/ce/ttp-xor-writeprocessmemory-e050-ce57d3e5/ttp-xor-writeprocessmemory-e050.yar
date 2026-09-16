rule TTP_XOR_WriteProcessMemory_e050 {
  strings:
    $key_e050 = { b7 22 [2] 85 00 [2] 83 35 [2] ad 35 [2] 92 29 }

  condition:
    any of them
}