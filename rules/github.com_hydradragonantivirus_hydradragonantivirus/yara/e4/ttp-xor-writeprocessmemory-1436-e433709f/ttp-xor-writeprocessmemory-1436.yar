rule TTP_XOR_WriteProcessMemory_1436 {
  strings:
    $key_1436 = { 43 44 [2] 71 66 [2] 77 53 [2] 59 53 [2] 66 4f }

  condition:
    any of them
}