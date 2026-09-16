rule TTP_XOR_WriteProcessMemory_79d2 {
  strings:
    $key_79d2 = { 2e a0 [2] 1c 82 [2] 1a b7 [2] 34 b7 [2] 0b ab }

  condition:
    any of them
}