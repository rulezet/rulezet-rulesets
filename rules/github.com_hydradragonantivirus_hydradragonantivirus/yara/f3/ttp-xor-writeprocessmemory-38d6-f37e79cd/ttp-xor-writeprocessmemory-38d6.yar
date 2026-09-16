rule TTP_XOR_WriteProcessMemory_38d6 {
  strings:
    $key_38d6 = { 6f a4 [2] 5d 86 [2] 5b b3 [2] 75 b3 [2] 4a af }

  condition:
    any of them
}