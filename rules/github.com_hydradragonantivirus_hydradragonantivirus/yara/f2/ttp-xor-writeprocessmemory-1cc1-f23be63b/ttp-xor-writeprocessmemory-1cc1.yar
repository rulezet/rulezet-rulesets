rule TTP_XOR_WriteProcessMemory_1cc1 {
  strings:
    $key_1cc1 = { 4b b3 [2] 79 91 [2] 7f a4 [2] 51 a4 [2] 6e b8 }

  condition:
    any of them
}