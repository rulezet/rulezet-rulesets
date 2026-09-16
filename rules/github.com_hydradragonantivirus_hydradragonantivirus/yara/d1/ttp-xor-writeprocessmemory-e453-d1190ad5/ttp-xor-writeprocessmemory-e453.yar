rule TTP_XOR_WriteProcessMemory_e453 {
  strings:
    $key_e453 = { b3 21 [2] 81 03 [2] 87 36 [2] a9 36 [2] 96 2a }

  condition:
    any of them
}