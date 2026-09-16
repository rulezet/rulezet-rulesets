rule TTP_XOR_WriteProcessMemory_3bb9 {
  strings:
    $key_3bb9 = { 6c cb [2] 5e e9 [2] 58 dc [2] 76 dc [2] 49 c0 }

  condition:
    any of them
}