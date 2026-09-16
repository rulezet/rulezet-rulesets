rule TTP_XOR_WriteProcessMemory_ea46 {
  strings:
    $key_ea46 = { bd 34 [2] 8f 16 [2] 89 23 [2] a7 23 [2] 98 3f }

  condition:
    any of them
}