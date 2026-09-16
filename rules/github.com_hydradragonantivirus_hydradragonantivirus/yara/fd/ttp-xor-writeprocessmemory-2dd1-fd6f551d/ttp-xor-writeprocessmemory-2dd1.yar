rule TTP_XOR_WriteProcessMemory_2dd1 {
  strings:
    $key_2dd1 = { 7a a3 [2] 48 81 [2] 4e b4 [2] 60 b4 [2] 5f a8 }

  condition:
    any of them
}