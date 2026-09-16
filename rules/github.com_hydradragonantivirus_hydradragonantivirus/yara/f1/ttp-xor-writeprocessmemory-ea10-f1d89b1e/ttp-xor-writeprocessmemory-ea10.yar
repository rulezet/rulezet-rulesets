rule TTP_XOR_WriteProcessMemory_ea10 {
  strings:
    $key_ea10 = { bd 62 [2] 8f 40 [2] 89 75 [2] a7 75 [2] 98 69 }

  condition:
    any of them
}