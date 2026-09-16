rule TTP_XOR_WriteProcessMemory_e072 {
  strings:
    $key_e072 = { b7 00 [2] 85 22 [2] 83 17 [2] ad 17 [2] 92 0b }

  condition:
    any of them
}