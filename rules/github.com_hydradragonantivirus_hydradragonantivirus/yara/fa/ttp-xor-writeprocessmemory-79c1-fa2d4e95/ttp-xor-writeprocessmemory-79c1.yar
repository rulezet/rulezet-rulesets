rule TTP_XOR_WriteProcessMemory_79c1 {
  strings:
    $key_79c1 = { 2e b3 [2] 1c 91 [2] 1a a4 [2] 34 a4 [2] 0b b8 }

  condition:
    any of them
}