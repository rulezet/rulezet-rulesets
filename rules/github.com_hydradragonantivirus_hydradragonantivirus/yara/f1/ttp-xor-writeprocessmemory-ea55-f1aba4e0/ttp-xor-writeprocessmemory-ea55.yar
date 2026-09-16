rule TTP_XOR_WriteProcessMemory_ea55 {
  strings:
    $key_ea55 = { bd 27 [2] 8f 05 [2] 89 30 [2] a7 30 [2] 98 2c }

  condition:
    any of them
}