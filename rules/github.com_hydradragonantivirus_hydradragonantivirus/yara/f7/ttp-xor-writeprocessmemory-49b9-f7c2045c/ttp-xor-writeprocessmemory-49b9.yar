rule TTP_XOR_WriteProcessMemory_49b9 {
  strings:
    $key_49b9 = { 1e cb [2] 2c e9 [2] 2a dc [2] 04 dc [2] 3b c0 }

  condition:
    any of them
}