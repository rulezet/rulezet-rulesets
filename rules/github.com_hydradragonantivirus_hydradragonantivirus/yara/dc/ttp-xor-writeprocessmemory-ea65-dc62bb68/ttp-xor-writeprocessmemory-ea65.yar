rule TTP_XOR_WriteProcessMemory_ea65 {
  strings:
    $key_ea65 = { bd 17 [2] 8f 35 [2] 89 00 [2] a7 00 [2] 98 1c }

  condition:
    any of them
}