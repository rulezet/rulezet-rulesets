rule TTP_XOR_WriteProcessMemory_e0d6 {
  strings:
    $key_e0d6 = { b7 a4 [2] 85 86 [2] 83 b3 [2] ad b3 [2] 92 af }

  condition:
    any of them
}