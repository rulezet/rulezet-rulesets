rule TTP_XOR_WriteProcessMemory_e063 {
  strings:
    $key_e063 = { b7 11 [2] 85 33 [2] 83 06 [2] ad 06 [2] 92 1a }

  condition:
    any of them
}