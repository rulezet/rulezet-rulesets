rule TTP_XOR_WriteProcessMemory_edb9 {
  strings:
    $key_edb9 = { ba cb [2] 88 e9 [2] 8e dc [2] a0 dc [2] 9f c0 }

  condition:
    any of them
}