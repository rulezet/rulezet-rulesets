rule TTP_XOR_WriteProcessMemory_49d1 {
  strings:
    $key_49d1 = { 1e a3 [2] 2c 81 [2] 2a b4 [2] 04 b4 [2] 3b a8 }

  condition:
    any of them
}