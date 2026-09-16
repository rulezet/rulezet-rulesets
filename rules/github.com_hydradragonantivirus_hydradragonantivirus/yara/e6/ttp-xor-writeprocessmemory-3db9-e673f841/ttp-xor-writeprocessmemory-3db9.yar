rule TTP_XOR_WriteProcessMemory_3db9 {
  strings:
    $key_3db9 = { 6a cb [2] 58 e9 [2] 5e dc [2] 70 dc [2] 4f c0 }

  condition:
    any of them
}