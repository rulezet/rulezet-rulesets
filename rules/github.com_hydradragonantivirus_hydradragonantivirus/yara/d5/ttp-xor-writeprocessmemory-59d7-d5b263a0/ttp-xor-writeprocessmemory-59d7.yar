rule TTP_XOR_WriteProcessMemory_59d7 {
  strings:
    $key_59d7 = { 0e a5 [2] 3c 87 [2] 3a b2 [2] 14 b2 [2] 2b ae }

  condition:
    any of them
}