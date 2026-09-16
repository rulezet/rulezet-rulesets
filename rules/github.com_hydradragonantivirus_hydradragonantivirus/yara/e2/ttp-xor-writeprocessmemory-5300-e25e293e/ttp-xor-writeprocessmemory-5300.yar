rule TTP_XOR_WriteProcessMemory_5300 {
  strings:
    $key_5300 = { 04 72 [2] 36 50 [2] 30 65 [2] 1e 65 [2] 21 79 }

  condition:
    any of them
}