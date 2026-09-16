rule TTP_XOR_WriteProcessMemory_e040 {
  strings:
    $key_e040 = { b7 32 [2] 85 10 [2] 83 25 [2] ad 25 [2] 92 39 }

  condition:
    any of them
}