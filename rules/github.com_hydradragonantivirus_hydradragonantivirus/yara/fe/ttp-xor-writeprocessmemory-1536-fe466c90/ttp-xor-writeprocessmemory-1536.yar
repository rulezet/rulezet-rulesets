rule TTP_XOR_WriteProcessMemory_1536 {
  strings:
    $key_1536 = { 42 44 [2] 70 66 [2] 76 53 [2] 58 53 [2] 67 4f }

  condition:
    any of them
}