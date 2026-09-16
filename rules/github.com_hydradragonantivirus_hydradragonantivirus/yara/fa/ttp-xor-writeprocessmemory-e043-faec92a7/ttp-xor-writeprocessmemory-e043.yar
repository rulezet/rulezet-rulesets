rule TTP_XOR_WriteProcessMemory_e043 {
  strings:
    $key_e043 = { b7 31 [2] 85 13 [2] 83 26 [2] ad 26 [2] 92 3a }

  condition:
    any of them
}