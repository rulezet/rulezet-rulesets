rule TTP_XOR_WriteProcessMemory_68d1 {
  strings:
    $key_68d1 = { 3f a3 [2] 0d 81 [2] 0b b4 [2] 25 b4 [2] 1a a8 }

  condition:
    any of them
}