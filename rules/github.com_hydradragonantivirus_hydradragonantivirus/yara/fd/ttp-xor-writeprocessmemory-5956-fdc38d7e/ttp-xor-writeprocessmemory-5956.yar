rule TTP_XOR_WriteProcessMemory_5956 {
  strings:
    $key_5956 = { 0e 24 [2] 3c 06 [2] 3a 33 [2] 14 33 [2] 2b 2f }

  condition:
    any of them
}