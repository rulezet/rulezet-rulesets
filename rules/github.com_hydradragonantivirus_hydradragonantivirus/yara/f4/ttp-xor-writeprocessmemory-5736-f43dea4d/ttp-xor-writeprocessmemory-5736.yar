rule TTP_XOR_WriteProcessMemory_5736 {
  strings:
    $key_5736 = { 00 44 [2] 32 66 [2] 34 53 [2] 1a 53 [2] 25 4f }

  condition:
    any of them
}