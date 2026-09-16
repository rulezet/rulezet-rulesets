rule TTP_XOR_WriteProcessMemory_ea06 {
  strings:
    $key_ea06 = { bd 74 [2] 8f 56 [2] 89 63 [2] a7 63 [2] 98 7f }

  condition:
    any of them
}