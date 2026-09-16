rule TTP_XOR_WriteProcessMemory_59d2 {
  strings:
    $key_59d2 = { 0e a0 [2] 3c 82 [2] 3a b7 [2] 14 b7 [2] 2b ab }

  condition:
    any of them
}