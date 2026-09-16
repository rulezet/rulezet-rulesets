rule TTP_XOR_WriteProcessMemory_59d1 {
  strings:
    $key_59d1 = { 0e a3 [2] 3c 81 [2] 3a b4 [2] 14 b4 [2] 2b a8 }

  condition:
    any of them
}