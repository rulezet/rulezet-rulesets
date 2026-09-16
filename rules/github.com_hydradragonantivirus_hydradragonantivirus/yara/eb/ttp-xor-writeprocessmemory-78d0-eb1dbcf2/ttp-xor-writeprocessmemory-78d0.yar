rule TTP_XOR_WriteProcessMemory_78d0 {
  strings:
    $key_78d0 = { 2f a2 [2] 1d 80 [2] 1b b5 [2] 35 b5 [2] 0a a9 }

  condition:
    any of them
}