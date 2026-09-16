rule TTP_XOR_WriteProcessMemory_09b9 {
  strings:
    $key_09b9 = { 5e cb [2] 6c e9 [2] 6a dc [2] 44 dc [2] 7b c0 }

  condition:
    any of them
}