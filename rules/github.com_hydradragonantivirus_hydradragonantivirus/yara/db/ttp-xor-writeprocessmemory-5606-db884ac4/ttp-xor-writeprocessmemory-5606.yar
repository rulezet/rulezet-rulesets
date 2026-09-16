rule TTP_XOR_WriteProcessMemory_5606 {
  strings:
    $key_5606 = { 01 74 [2] 33 56 [2] 35 63 [2] 1b 63 [2] 24 7f }

  condition:
    any of them
}