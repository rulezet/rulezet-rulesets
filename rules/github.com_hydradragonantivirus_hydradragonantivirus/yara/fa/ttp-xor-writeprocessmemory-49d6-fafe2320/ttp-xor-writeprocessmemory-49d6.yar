rule TTP_XOR_WriteProcessMemory_49d6 {
  strings:
    $key_49d6 = { 1e a4 [2] 2c 86 [2] 2a b3 [2] 04 b3 [2] 3b af }

  condition:
    any of them
}