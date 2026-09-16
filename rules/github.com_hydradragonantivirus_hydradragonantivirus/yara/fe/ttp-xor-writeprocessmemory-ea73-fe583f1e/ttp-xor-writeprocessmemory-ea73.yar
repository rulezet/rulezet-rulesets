rule TTP_XOR_WriteProcessMemory_ea73 {
  strings:
    $key_ea73 = { bd 01 [2] 8f 23 [2] 89 16 [2] a7 16 [2] 98 0a }

  condition:
    any of them
}