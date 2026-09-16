rule TTP_XOR_WriteProcessMemory_08d6 {
  strings:
    $key_08d6 = { 5f a4 [2] 6d 86 [2] 6b b3 [2] 45 b3 [2] 7a af }

  condition:
    any of them
}