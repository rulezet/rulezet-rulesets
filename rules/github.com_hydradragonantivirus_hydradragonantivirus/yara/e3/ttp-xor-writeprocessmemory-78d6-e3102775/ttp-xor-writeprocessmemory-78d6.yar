rule TTP_XOR_WriteProcessMemory_78d6 {
  strings:
    $key_78d6 = { 2f a4 [2] 1d 86 [2] 1b b3 [2] 35 b3 [2] 0a af }

  condition:
    any of them
}