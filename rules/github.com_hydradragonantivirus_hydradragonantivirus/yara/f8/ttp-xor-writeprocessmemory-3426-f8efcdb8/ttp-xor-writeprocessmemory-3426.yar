rule TTP_XOR_WriteProcessMemory_3426 {
  strings:
    $key_3426 = { 63 54 [2] 51 76 [2] 57 43 [2] 79 43 [2] 46 5f }

  condition:
    any of them
}