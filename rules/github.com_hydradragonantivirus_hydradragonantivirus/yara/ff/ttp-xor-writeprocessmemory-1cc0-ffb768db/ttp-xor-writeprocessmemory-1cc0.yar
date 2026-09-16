rule TTP_XOR_WriteProcessMemory_1cc0 {
  strings:
    $key_1cc0 = { 4b b2 [2] 79 90 [2] 7f a5 [2] 51 a5 [2] 6e b9 }

  condition:
    any of them
}