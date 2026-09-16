rule TTP_XOR_WriteProcessMemory_13e7 {
  strings:
    $key_13e7 = { 44 95 [2] 76 b7 [2] 70 82 [2] 5e 82 [2] 61 9e }

  condition:
    any of them
}