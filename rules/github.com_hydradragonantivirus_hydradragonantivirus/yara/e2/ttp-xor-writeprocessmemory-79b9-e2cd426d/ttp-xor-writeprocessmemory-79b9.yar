rule TTP_XOR_WriteProcessMemory_79b9 {
  strings:
    $key_79b9 = { 2e cb [2] 1c e9 [2] 1a dc [2] 34 dc [2] 0b c0 }

  condition:
    any of them
}