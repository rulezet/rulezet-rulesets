rule TTP_XOR_WriteProcessMemory_7856 {
  strings:
    $key_7856 = { 2f 24 [2] 1d 06 [2] 1b 33 [2] 35 33 [2] 0a 2f }

  condition:
    any of them
}