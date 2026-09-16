rule TTP_XOR_WriteProcessMemory_29b9 {
  strings:
    $key_29b9 = { 7e cb [2] 4c e9 [2] 4a dc [2] 64 dc [2] 5b c0 }

  condition:
    any of them
}