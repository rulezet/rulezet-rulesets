rule TTP_XOR_WriteProcessMemory_68c4 {
  strings:
    $key_68c4 = { 3f b6 [2] 0d 94 [2] 0b a1 [2] 25 a1 [2] 1a bd }

  condition:
    any of them
}