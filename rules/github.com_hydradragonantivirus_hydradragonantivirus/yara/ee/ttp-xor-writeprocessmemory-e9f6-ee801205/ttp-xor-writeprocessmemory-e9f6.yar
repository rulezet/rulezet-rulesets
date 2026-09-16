rule TTP_XOR_WriteProcessMemory_e9f6 {
  strings:
    $key_e9f6 = { be 84 [2] 8c a6 [2] 8a 93 [2] a4 93 [2] 9b 8f }

  condition:
    any of them
}